from re import L  # Unused—consider removing or fixing (e.g., import re)
from typing import List, Optional, Dict
import os
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_DELETE
from dotenv import load_dotenv
 
# Load repo .env
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(ROOT, ".env"))
load_dotenv(os.path.join(ROOT, ".env"), override=True)
 
def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y")
 
# # Use os.getenv() for all configs—strip strings to prevent DN issues
# DB_NAME = os.getenv("DB_NAME", "kjhgf").strip()
# DB_USER = os.getenv("DB_USER", "kjh").strip()
# DB_PASSWORD = os.getenv("DB_PASSWORD", "nbjv").strip()
# DB_HOST = os.getenv("DB_HOST", "kjhggvhbjkl.jhgf.com").strip()
# DB_PORT = int(os.getenv("DB_PORT", "5432"))
 
# LDAP_SERVER_URI = os.getenv("LDAP_SERVER_URI", "ldapkjhg").strip()
# LDAP_ORG_UNIT = os.getenv("LDAP_ORG_UNIT", "ou=INTERNAL, ou=PEOPLE, ou=VAULT, o=JNJ").strip()
# LDAP_SEARCH_ATTRIBUTE = os.getenv("LDAP_SEARCH_ATTRIBUTE", "sAMAccountName").strip()  # Fixed placeholder
# LDAP_GROUP_ATTRIBUTE = os.getenv("LDAP_GROUP_ATTRIBUTE", "member").strip()  # Added—used in _is_member_of_allowed_group but missing
# LDAP_SERVER_AVAILABLE = _bool_env("LDAP_SERVER_AVAILABLE", True)
# LDAP_GROUP_FILTER = _bool_env("LDAP_GROUP_FILTER", True)
# LDAP_ALLOWED_GROUPS = os.getenv("LDAP_ALLOWED_GROUPS", "JRD-AUTOCODE-DEV-ADMIN,JRD-AUTOCODE-DEV").strip()
 
 
DB_NAME="autocode_adam_p2"
DB_USER="autocode_adam_p2"
DB_PASSWORD="AdAm32M156"
DB_HOST="autocodedev2.crilo1infm0a.us-east-1.rds.amazonaws.com"
DB_PORT=5432
 
LDAP_SERVER_URI="ldap://ldap-idv.psso.its.jnj.com:389"
LDAP_ORG_UNIT="ou=INTERNAL, ou=PEOPLE, ou=VAULT, o=JNJ"
LDAP_SEARCH_ATTRIBUTE="jnjmsusername"
LDAP_SERVER_AVAILABLE=True
LDAP_GROUP_FILTER=True
LDAP_ALLOWED_GROUPS='JRD-AUTOCODE-DEV-ADMIN,JRD-AUTOCODE-DEV'
 
# Shared stripped search base—prevents DN parsing errors globally
SEARCH_BASE = LDAP_ORG_UNIT if LDAP_ORG_UNIT else ""
SEARCH_BASE = ','.join(part.strip() for part in SEARCH_BASE.split(','))
 
 
 
app = FastAPI(title="User Manager (DB/LDAP aware)", docs_url="/authenticate/docs")
 
class UserOut(BaseModel):
    id: Optional[int]
    username: Optional[str]
    email: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    dn: Optional[str] = None
 
class AssignRequest(BaseModel):
    identifier: str
    identifier_type: Optional[str] = "username"
    action: str  # 'assign'|'remove'
    target_type: str
    target: str
 
# ---------- DB helpers ----------
def get_db_connection():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
 
def search_db_users(query: str, limit: int = 25) -> List[UserOut]:
    try:
        q = f"%{query}%"
        with get_db_connection() as conn:  # Use 'with' for auto-close
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                """
                SELECT id, username, email, first_name, last_name
                FROM auth_user
                WHERE username ILIKE %s OR email ILIKE %s OR (first_name || ' ' || last_name) ILIKE %s
                ORDER BY username
                LIMIT %s
                """,
                (q, q, q, limit),
            )
            rows = cur.fetchall()
            return [UserOut(**r) for r in rows]
    except Exception as e:
        import traceback
        traceback.print_exc()
        return []
 
def assign_db_group(username: str, group_name: str, action: str):
    try:
        with get_db_connection() as conn:  # Use 'with' for auto-close
            cur = conn.cursor()
            cur.execute("SELECT id FROM auth_user WHERE username=%s", (username,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="DB user not found")
            user_id = u[0]
            cur.execute("SELECT id FROM auth_group WHERE name=%s", (group_name,))
            g = cur.fetchone()
            if not g:
                raise HTTPException(status_code=404, detail="DB group not found")
            group_id = g[0]
            if action == "assign":
                cur.execute(
                    """
                    INSERT INTO auth_user_groups (user_id, group_id)
                    SELECT %s, %s
                    WHERE NOT EXISTS (
                        SELECT 1 FROM auth_user_groups WHERE user_id=%s AND group_id=%s
                    )
                    """,
                    (user_id, group_id, user_id, group_id),
                )
            else:
                cur.execute("DELETE FROM auth_user_groups WHERE user_id=%s AND group_id=%s", (user_id, group_id))
            conn.commit()
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"DB assignment failed: {e}")
 
def ensure_assignment_table_exists():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_assignments (
                id serial PRIMARY KEY,
                user_id integer NOT NULL,
                target_type varchar(64) NOT NULL,
                target_id varchar(128) NOT NULL,
                UNIQUE(user_id, target_type, target_id)
            );
            """
        )
        conn.commit()
 
def assign_db_generic(identifier: str, identifier_type: str, action: str, target_type: str, target: str):
    ensure_assignment_table_exists()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            if identifier_type == "id":
                cur.execute("SELECT id FROM auth_user WHERE id=%s", (int(identifier),))
            else:
                cur.execute("SELECT id FROM auth_user WHERE username=%s", (identifier,))
            r = cur.fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="DB user not found")
            user_id = r[0]
            if action == "assign":
                cur.execute(
                    """
                    INSERT INTO user_assignments (user_id, target_type, target_id)
                    SELECT %s, %s, %s
                    WHERE NOT EXISTS (
                      SELECT 1 FROM user_assignments WHERE user_id=%s AND target_type=%s AND target_id=%s
                    )
                    """,
                    (user_id, target_type, target, user_id, target_type, target),
                )
            else:
                cur.execute("DELETE FROM user_assignments WHERE user_id=%s AND target_type=%s AND target_id=%s", (user_id, target_type, target))
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB generic assignment failed: {e}")
 
# ---------- LDAP helpers ----------
def ldap_connect() -> Connection:
    if not LDAP_SERVER_URI:
        raise HTTPException(status_code=500, detail="LDAP not configured (LDAP_SERVER_URI missing)")
    server = Server(LDAP_SERVER_URI, get_info=ALL)
    try:
        if "LDAP_BIND_DN" in os.environ and "LDAP_BIND_PASSWORD" in os.environ:
            bind_dn = os.getenv("LDAP_BIND_DN", "").strip()
            bind_pw = os.getenv("LDAP_BIND_PASSWORD", "").strip()
            if bind_dn and bind_pw:
                conn = Connection(server, user=bind_dn, password=bind_pw, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)
        else:
            conn = Connection(server, auto_bind=True)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"LDAP bind failed: {e}")
    return conn
 
def _is_member_of_allowed_group(conn: Connection, user_dn: str) -> bool:
    if not LDAP_GROUP_FILTER or not LDAP_ALLOWED_GROUPS:
        return True
    allowed = [g.strip().strip("'\"") for g in LDAP_ALLOWED_GROUPS.split(",") if g.strip()]
    for grp in allowed:
        grp_filter = f"(&(objectClass=group)(cn={grp})({LDAP_GROUP_ATTRIBUTE}={user_dn}))"
        conn.search(SEARCH_BASE, grp_filter, SUBTREE, attributes=['distinguishedName'])  # Use shared SEARCH_BASE
        if conn.entries:
            return True
    return False
 
def search_ldap(query: str, limit: int = 25) -> List[UserOut]:
    conn = None
    try:
        if not SEARCH_BASE:
            raise HTTPException(status_code=400, detail="LDAP search base (ORG_UNIT) is empty or invalid")
 
        conn = ldap_connect()
        attr = LDAP_SEARCH_ATTRIBUTE or "sAMAccountName"
        ldap_filter = f"(|({attr}=*{query}*)(cn=*{query}*)(mail=*{query}*))"
        conn.search(
            SEARCH_BASE,
            ldap_filter,
            SUBTREE,
            attributes=['jnjmsusername', 'cn', 'mail', 'distinguishedName', 'givenName', 'sn', 'memberOf'],
            size_limit=limit
        )
 
        results: List[UserOut] = []
 
        for idx, entry in enumerate(conn.entries, start=1):
            e = entry.entry_attributes_as_dict
 
            dn_list = e.get('distinguishedName')
            if isinstance(dn_list, list) and dn_list:
                dn = dn_list[0]
            else:
                dn = e.get('distinguishedName') or entry.entry_dn or ""
 
            if not dn:
                continue
 
            username = e.get('jnjmsusername', [None])[0] if isinstance(e.get('jnjmsusername', None), list) else e.get('jnjmsusername')
 
            results.append(UserOut(
                id=idx,  # ✅ Added
                dn=dn,
                username=username,
                email=e.get('mail', [None])[0] if isinstance(e.get('mail', None), list) else e.get('mail'),
                first_name=e.get('givenName', [None])[0] if isinstance(e.get('givenName', None), list) else e.get('givenName'),
                last_name=e.get('sn', [None])[0] if isinstance(e.get('sn', None), list) else e.get('sn'),
            ))
 
        return results
 
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"LDAP search failed: {e}")
 
    finally:
        if conn:
            conn.unbind()
 
def find_ldap_group_dn_by_name(group_name: str) -> str:
    conn = None
    try:
        if not SEARCH_BASE:  # Guard against empty base
            raise HTTPException(status_code=400, detail="LDAP search base (ORG_UNIT) is empty or invalid")
        conn = ldap_connect()
        filter_ = f"(&(objectClass=group)(cn={group_name}))"
        conn.search(SEARCH_BASE, filter_, SUBTREE, attributes=['distinguishedName'])  # Use shared SEARCH_BASE
        if not conn.entries:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        return conn.entries[0].entry_dn
    finally:
        if conn:
            conn.unbind()
 
 
 
# ---------- API endpoints ----------
@app.get("/authenticate/user/search", response_model=List[UserOut])
def user_search(q: str = Query(..., min_length=1), limit: int = 25):
    if LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER:
        return search_ldap(q, limit)
    return search_db_users(q, limit)
 
 
 
@app.get("/authenticate/ldap_users/search", response_model=List[UserOut])
def ldap_users_search(q: str = Query(..., min_length=1), limit: int = 25):
    """
    Explicit LDAP search endpoint. Returns 400 if LDAP not enabled.
    """
    if not (LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER):
        raise HTTPException(status_code=400, detail="LDAP not enabled in configuration")
    return search_ldap(q, limit)
 
# health
@app.get("/authenticate/health")
def health():
    return {"ok": True, "ldap": LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER}
 