"""Read-only Microsoft Graph access to the Pearson lab tenant."""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

GRAPH = "https://graph.microsoft.com/v1.0"
_token = None


def _get_token() -> str:
    """App-only (client credentials) token for Microsoft Graph."""
    global _token
    if _token:
        return _token
    url = f"https://login.microsoftonline.com/{os.environ['AZ_TENANT_ID']}/oauth2/v2.0/token"
    data = {
        "client_id": os.environ["AZ_CLIENT_ID"],
        "client_secret": os.environ["AZ_CLIENT_SECRET"],
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=30)
    r.raise_for_status()
    _token = r.json()["access_token"]
    return _token


def _get(path: str, params: dict | None = None) -> list[dict]:
    """GET a Graph collection, following @odata.nextLink pagination."""
    headers = {"Authorization": f"Bearer {_get_token()}"}
    url = f"{GRAPH}{path}"
    items: list[dict] = []
    while url:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        body = r.json()
        items.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
        params = None  # nextLink already carries the query
    return items


# ---- Audit read-only helpers --------------------------------------------

def list_users() -> list[dict]:
    """All users with key attributes."""
    return _get("/users", {
        "$select": "id,displayName,userPrincipalName,accountEnabled,userType",
        "$top": "999",
    })


def list_guest_users() -> list[dict]:
    return [u for u in list_users() if u.get("userType") == "Guest"]


def list_directory_roles() -> list[dict]:
    """Active directory roles in the tenant."""
    return _get("/directoryRoles")


def list_role_members(role_template_display_name: str = "Global Administrator") -> list[dict]:
    """Members of a given directory role (e.g. Global Administrator)."""
    roles = list_directory_roles()
    role = next((r for r in roles if r.get("displayName") == role_template_display_name), None)
    if not role:
        return []
    return _get(f"/directoryRoles/{role['id']}/members")


def list_global_admins() -> list[dict]:
    return list_role_members("Global Administrator")


def list_conditional_access_policies() -> list[dict]:
    return _get("/identity/conditionalAccess/policies")


def list_service_principals() -> list[dict]:
    return _get("/servicePrincipals", {
        "$select": "id,displayName,appId,servicePrincipalType,accountEnabled",
        "$top": "999",
    })


if __name__ == "__main__":
    admins = list_global_admins()
    print(f"Global Admins ({len(admins)}):")
    for a in admins:
        print("  -", a.get("displayName"), a.get("userPrincipalName", ""))






def list_privileged_owners():
    """Ownership-based privilege-escalation paths: users who OWN a service
    principal or group that itself holds a directory role. Read-only.
    Walks SP/group -> memberOf (roles) + owners, which is the reliable direction."""
    paths = []

    def _check(kind, base, items):
        for obj in items:
            oid, oname = obj.get("id"), obj.get("displayName")
            roles = [r.get("displayName") for r in _get(f"/{base}/{oid}/memberOf")
                     if "directoryRole" in r.get("@odata.type", "")]
            if not roles:
                continue
            for o in _get(f"/{base}/{oid}/owners"):
                if o.get("@odata.type", "").endswith("user"):
                    paths.append({
                        "owner": o.get("userPrincipalName") or o.get("displayName"),
                        "owned_object": oname,
                        "object_type": kind,
                        "privileged_roles": roles,
                    })

    _check("servicePrincipal", "servicePrincipals", _get("/servicePrincipals"))
    _check("group", "groups", _get("/groups"))
    return {"escalation_paths": paths, "count": len(paths)}
