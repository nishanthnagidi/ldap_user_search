# main.py
from typing import List, Optional
import os
import json

from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_DELETE
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

# configuration flags from your repo .env
LDAP_SERVER_AVAILABLE = os.getenv("LDAP_SERVER_AVAILABLE", "False") == "True"
LDAP_GROUP_FILTER = os.getenv("LDAP_GROUP_FILTER", "False") == "True"

# Postgres connection settings (reuse repo .env)
DB_NAME = os.getenv("DB_NAME", "ADaM")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))

# LDAP settings (optional, only used when LDAP_SERVER_AVAILABLE=True)
LDAP_URI = os.getenv("LDAP_SERVER_URI", "")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "")  # e.g. "dc=example,dc=com"
LDAP_USER_FILTER = os.getenv("LDAP_USER_FILTER", "(objectClass=person)")
LDAP_GROUP_ATTR = os.getenv("LDAP_GROUP_ATTRIBUTE", "member")  # attribute storing members
LDAP_GROUP_DN_PREFIX = os.getenv("LDAP_GROUP_DN_PREFIX", "")  # optional prefix

app = FastAPI(title="User Manager (DB/LDAP aware)")

# ---------- simple DTOs ----------
class UserOut(BaseModel):
    id: Optional[int]
    username: Optional[str]
    email: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    dn: Optional[str] = None

class AssignRequest(BaseModel):
    identifier: str  # username or user id or DN depending on mode
    identifier_type: Optional[str] = "username"  # 'id'|'username'|'dn'
    action: str  # 'assign' or 'remove'
    target_type: str  # e.g. 'group' or 'study' (group supported for LDAP)
    target: str  # group name or study id (string)

# ---------- helpers ----------
def get_db_connection():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )

def search_db_users(query: str, limit: int = 25) -> List[UserOut]:
    q = f"%{query}%"
    conn = get_db_connection()
    try:
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
    finally:
        conn.close()

def assign_db_group(username: str, group_name: str, action: str):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # find user
        cur.execute("SELECT id FROM auth_user WHERE username=%s", (username,))
        u = cur.fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="DB user not found")
        user_id = u[0]
        # find group id
        cur.execute("SELECT id FROM auth_group WHERE name=%s", (group_name,))
        g = cur.fetchone()
        if not g:
            raise HTTPException(status_code=404, detail="DB group not found")
        group_id = g[0]
        if action == "assign":
            # insert if not exists
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
            cur.execute(
                "DELETE FROM auth_user_groups WHERE user_id=%s AND group_id=%s",
                (user_id, group_id),
            )
        conn.commit()
    finally:
        conn.close()

def ensure_assignment_table_exists():
    # optional helper to create a generic assignment table for study assignments
    conn = get_db_connection()
    try:
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
    finally:
        conn.close()

def assign_db_generic(identifier: str, identifier_type: str, action: str, target_type: str, target: str):
    # supports assigning users to arbitrary targets (e.g., studies) in a simple table
    ensure_assignment_table_exists()
    conn = get_db_connection()
    try:
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
        elif action == "remove":
            cur.execute(
                "DELETE FROM user_assignments WHERE user_id=%s AND target_type=%s AND target_id=%s",
                (user_id, target_type, target),
            )
        conn.commit()
    finally:
        conn.close()

# ---------- LDAP helpers ----------
def ldap_connect():
    if not LDAP_URI:
        raise HTTPException(status_code=500, detail="LDAP not configured")
    server = Server(LDAP_URI, get_info=ALL)
    conn = Connection(server, user=LDAP_BIND_DN or None, password=LDAP_BIND_PASSWORD or None, auto_bind=True)
    return conn

def search_ldap(query: str, limit: int = 25) -> List[UserOut]:
    conn = ldap_connect()
    try:
        ldap_filter = f"(|(cn=*{query}*)(sAMAccountName=*{query}*)(mail=*{query}*))"
        conn.search(LDAP_SEARCH_BASE or "", ldap_filter, SUBTREE, attributes=['cn','sAMAccountName','mail','distinguishedName','givenName','sn'], size_limit=limit)
        results = []
        for entry in conn.entries:
            e = entry.entry_attributes_as_dict
            results.append(UserOut(
                dn=e.get('distinguishedName',[None])[0],
                username=e.get('sAMAccountName',[None])[0],
                email=e.get('mail',[None])[0],
                first_name=e.get('givenName',[None])[0],
                last_name=e.get('sn',[None])[0],
            ))
        return results
    finally:
        conn.unbind()

def modify_ldap_group_membership(group_dn: str, user_dn: str, action: str):
    conn = ldap_connect()
    try:
        if action == "assign":
            changes = {LDAP_GROUP_ATTR: [(MODIFY_ADD, [user_dn])]}
        else:
            changes = {LDAP_GROUP_ATTR: [(MODIFY_DELETE, [user_dn])]}
        ok = conn.modify(group_dn, changes)
        if not ok:
            raise HTTPException(status_code=400, detail=f"LDAP modify failed: {conn.result}")
        return conn.result
    finally:
        conn.unbind()

def find_ldap_group_dn_by_name(group_name: str) -> str:
    conn = ldap_connect()
    try:
        # naive search: look for objectClass group with cn=group_name
        filter_ = f"(&(objectClass=group)(cn={group_name}))"
        conn.search(LDAP_SEARCH_BASE or "", filter_, SUBTREE, attributes=['distinguishedName'])
        if not conn.entries:
            raise HTTPException(status_code=404, detail="LDAP group not found")
        return conn.entries[0].entry_dn
    finally:
        conn.unbind()

# ---------- API endpoints ----------
@app.get("/user/search", response_model=List[UserOut])
def user_search(q: str = Query(..., min_length=1), limit: int = 25):
    """
    Search users. Behavior depends on LDAP flags:
      - If LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER are True -> search LDAP
      - Otherwise -> search local auth_user table
    """
    if LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER:
        return search_ldap(q, limit)
    return search_db_users(q, limit)

@app.post("/user/assign")
def user_assign(req: AssignRequest = Body(...)):
    """
    Assign or remove a user to/from a target.
    - In DB mode (LDAP disabled): supports 'group' via auth_group/auth_user_groups
      and generic 'study' (or other target) via a lightweight user_assignments table.
    - In LDAP mode: supports 'group' (adds/removes member DN from LDAP group).
    """
    if LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER:
        # LDAP flow: only group assignments supported here
        if req.target_type != "group":
            raise HTTPException(status_code=400, detail="LDAP mode supports only target_type=group")
        # resolve user DN
        if req.identifier_type == "dn":
            user_dn = req.identifier
        else:
            # search LDAP for identifier
            matches = search_ldap(req.identifier, limit=1)
            if not matches:
                raise HTTPException(status_code=404, detail="LDAP user not found")
            user_dn = matches[0].dn
            if not user_dn:
                raise HTTPException(status_code=404, detail="LDAP user DN not found")
        group_dn = find_ldap_group_dn_by_name(req.target)
        res = modify_ldap_group_membership(group_dn, user_dn, req.action)
        return {"status": "ok", "result": res}
    else:
        # DB flow
        if req.target_type == "group":
            # simple DB group assign/remove
            identifier = req.identifier
            id_type = req.identifier_type
            if id_type == "id":
                # convert id to username
                conn = get_db_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT username FROM auth_user WHERE id=%s", (int(identifier),))
                    r = cur.fetchone()
                    if not r:
                        raise HTTPException(status_code=404, detail="DB user not found")
                    identifier = r[0]
                finally:
                    conn.close()
            assign_db_group(identifier, req.target, req.action)
            return {"status": "ok"}
        else:
            # generic assignment (study etc.)
            assign_db_generic(req.identifier, req.identifier_type, req.action, req.target_type, req.target)
            return {"status": "ok"}

@app.get("/ldap_users/search", response_model=List[UserOut])
def ldap_users_search(q: str = Query(..., min_length=1), limit: int = 25):
    """
    Explicit LDAP search endpoint. Returns 400 if LDAP not enabled.
    """
    if not (LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER):
        raise HTTPException(status_code=400, detail="LDAP not enabled in configuration")
    return search_ldap(q, limit)

# health
@app.get("/health")
def health():
    return {"ok": True, "ldap": LDAP_SERVER_AVAILABLE and LDAP_GROUP_FILTER}




# import os
# from typing import List, Dict
# from fastapi import HTTPException
# from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD, MODIFY_DELETE

# # Read same env names used by the Django config
# LDAP_URI = os.getenv("LDAP_SERVER_URI", "")
# LDAP_SEARCH_BASE = os.getenv("LDAP_ORG_UNIT", "")            # AUTH_LDAP_ORG_UNIT
# SEARCH_ATTRIBUTE = os.getenv("LDAP_SEARCH_ATTRIBUTE", "sAMAccountName")
# LDAP_GROUP_FILTER = os.getenv("LDAP_GROUP_FILTER", "False").lower() in ("true","1","yes")
# LDAP_ALLOWED_GROUPS = os.getenv("LDAP_ALLOWED_GROUPS", "")
# LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "")
# LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
# LDAP_GROUP_ATTR = os.getenv("LDAP_GROUP_ATTRIBUTE", "member")  # group-of-names uses 'member'

# def ldap_connect() -> Connection:
#     if not LDAP_URI:
#         raise HTTPException(status_code=500, detail="LDAP not configured (LDAP_SERVER_URI missing)")
#     server = Server(LDAP_URI, get_info=ALL)
#     try:
#         conn = Connection(server, user=LDAP_BIND_DN or None, password=LDAP_BIND_PASSWORD or None, auto_bind=True)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"LDAP bind failed: {e}")
#     return conn

# def _is_member_of_allowed_group(conn: Connection, user_dn: str) -> bool:
#     if not LDAP_GROUP_FILTER or not LDAP_ALLOWED_GROUPS:
#         return True
#     allowed = [g.strip() for g in LDAP_ALLOWED_GROUPS.split(",") if g.strip()]
#     for grp in allowed:
#         grp_filter = f"(&(objectClass=group)(cn={grp})({LDAP_GROUP_ATTR}={user_dn}))"
#         conn.search(LDAP_SEARCH_BASE or "", grp_filter, SUBTREE, attributes=['distinguishedName'])
#         if conn.entries:
#             return True
#     return False

# def search_ldap(query: str, limit: int = 25) -> List[Dict]:
#     conn = ldap_connect()
#     try:
#         ldap_filter = f"(|({SEARCH_ATTRIBUTE}=*{query}*)(cn=*{query}*)(mail=*{query}*))"
#         conn.search(LDAP_SEARCH_BASE or "", ldap_filter, SUBTREE,
#                     attributes=[SEARCH_ATTRIBUTE, 'cn', 'mail', 'distinguishedName', 'givenName', 'sn', 'memberOf'],
#                     size_limit=limit)
#         results = []
#         for entry in conn.entries:
#             e = entry.entry_attributes_as_dict
#             dn = e.get('distinguishedName', [None])[0]
#             if not dn:
#                 continue
#             if LDAP_GROUP_FILTER and LDAP_ALLOWED_GROUPS:
#                 try:
#                     allowed = _is_member_of_allowed_group(conn, dn)
#                 except Exception:
#                     allowed = False
#                 if not allowed:
#                     continue
#             username = e.get(SEARCH_ATTRIBUTE, [None])[0] or e.get('sAMAccountName', [None])[0] or e.get('cn', [None])[0]
#             results.append({
#                 "dn": dn,
#                 "username": username,
#                 "email": e.get('mail', [None])[0],
#                 "first_name": e.get('givenName', [None])[0],
#                 "last_name": e.get('sn', [None])[0],
#             })
#         return results
#     finally:
#         conn.unbind()

# def find_ldap_group_dn_by_name(group_name: str) -> str:
#     conn = ldap_connect()
#     try:
#         filter_ = f"(&(objectClass=group)(cn={group_name}))"
#         conn.search(LDAP_SEARCH_BASE or "", filter_, SUBTREE, attributes=['distinguishedName'])
#         if not conn.entries:
#             raise HTTPException(status_code=404, detail="LDAP group not found")
#         return conn.entries[0].entry_dn
#     finally:
#         conn.unbind()

# def modify_ldap_group_membership(group_dn: str, user_dn: str, action: str):
#     conn = ldap_connect()
#     try:
#         if action == "assign":
#             changes = {LDAP_GROUP_ATTR: [(MODIFY_ADD, [user_dn])]}
#         else:
#             changes = {LDAP_GROUP_ATTR: [(MODIFY_DELETE, [user_dn])]}
#         ok = conn.modify(group_dn, changes)
#         if not ok:
#             raise HTTPException(status_code=400, detail=f"LDAP modify failed: {conn.result}")
#         return conn.result
#     finally:
#         conn.unbind()