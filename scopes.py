# scopes.py
import requests
from urllib.parse import urlencode

# ===============================
# CONFIG
# ===============================

GOOGLE_API_MAP = {
    "Gmail":    {"name": "gmail",    "version": "v1"},
    "Calendar": {"name": "calendar", "version": "v3"},
    "Drive":    {"name": "drive",    "version": "v3"},
    "Sheets":   {"name": "sheets",   "version": "v4"},
}

# Groupes de scopes (read / write) par service
SCOPE_GROUPS = {
    "Gmail": {
        "read":  ["https://www.googleapis.com/auth/gmail.readonly"],
        "write": ["https://www.googleapis.com/auth/gmail.send"],
    },
    "Calendar": {
        "read":  ["https://www.googleapis.com/auth/calendar.events.readonly"],
        "write": ["https://www.googleapis.com/auth/calendar.events"],
    },
    "Drive": {
        "read":  ["https://www.googleapis.com/auth/drive.readonly"],
        "write": ["https://www.googleapis.com/auth/drive.file"],  # écriture limitée
    },
    "Sheets": {
        "read":  ["https://www.googleapis.com/auth/spreadsheets.readonly"],
        "write": ["https://www.googleapis.com/auth/spreadsheets"],
    },
}

# Bundle "services → tous scopes read+write"
SERVICES = {
    svc: {
        "scopes": sorted(set(SCOPE_GROUPS[svc]["read"] + SCOPE_GROUPS[svc]["write"])),
        "info_gain": {
            "read":  f"{svc} read access",
            "write": f"{svc} write access",
            "both":  f"{svc} read & write access",
        }
    }
    for svc in SCOPE_GROUPS.keys()
}

# ===============================
# Scopes actuels d'un token
# ===============================

def get_token_scopes(access_token: str) -> list[str]:
    """Retourne la liste de scopes d'un access_token via tokeninfo."""
    try:
        r = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={access_token}", timeout=10)
        if r.status_code == 200:
            return r.json().get("scope", "").split()
        return []
    except Exception:
        return []

# ===============================
# Découverte des méthodes Google
# ===============================

def _fetch_discovery_rest(api_name: str, version: str) -> dict | None:
    """Récupère le JSON de discovery pour une API donnée."""
    url = f"https://www.googleapis.com/discovery/v1/apis/{api_name}/{version}/rest"
    r = requests.get(url, timeout=15)
    if r.status_code == 200:
        return r.json()
    return None

def _extract_methods(doc: dict) -> list[dict]:
    """
    Extrait toutes les méthodes (httpMethod, path, description, scopes) en parcourant récursivement resources.
    """
    methods = []

    def walk_resources(resources: dict, prefix: str = ""):
        if not resources:
            return
        for res_name, res in resources.items():
            new_prefix = prefix
            # Les methods ont un 'path' relatif (souvent sans le nom de res), on garde juste path fourni
            if "methods" in res:
                for mname, m in res["methods"].items():
                    methods.append({
                        "httpMethod": m.get("httpMethod", "GET"),
                        "path": m.get("path", ""),
                        "description": m.get("description", ""),
                        "scopes": m.get("scopes", []),
                    })
            # recurse
            if "resources" in res:
                walk_resources(res["resources"], new_prefix)

    walk_resources(doc.get("resources", {}))
    return methods

def discover_methods_for_service(service: str) -> list[dict]:
    """Télécharge et retourne la liste des méthodes pour un service (Gmail/Drive/Calendar/Sheets)."""
    meta = GOOGLE_API_MAP.get(service)
    if not meta:
        return []
    doc = _fetch_discovery_rest(meta["name"], meta["version"])
    if not doc:
        return []
    return _extract_methods(doc)

def filter_methods_by_scopes(methods: list[dict], candidate_scopes: list[str]) -> list[dict]:
    """
    Garde les méthodes dont AU MOINS un scope requis appartient à candidate_scopes.
    (Beaucoup de méthodes google déclarent un OU logique sur les scopes.)
    """
    cand = set(candidate_scopes)
    allowed = []
    for m in methods:
        req = set(m.get("scopes", []))
        if not req or (req & cand):
            allowed.append(m)
    return allowed

def count_methods(service: str, candidate_scopes: list[str]) -> tuple[int, list[dict]]:
    """Compte le nombre de méthodes accessibles pour un service donné avec un ensemble de scopes."""
    methods = discover_methods_for_service(service)
    allowed = filter_methods_by_scopes(methods, candidate_scopes)
    return len(allowed), allowed[:10]  # on renvoie quelques exemples

# ===============================
# Analyse des gaps par rapport aux services
# ===============================

def analyze_scope_gap(current_scopes: list[str]):
    """
    Retourne (résumé_par_service, missing_all_scopes)
    résumé_par_service: [{ service, read_missing, write_missing, both_missing, examples }]
    """
    results = []
    missing_all = []
    cur = set(current_scopes)

    for service, cfg in SCOPE_GROUPS.items():
        read_scopes  = cfg["read"]
        write_scopes = cfg["write"]

        read_missing  = [s for s in read_scopes  if s not in cur]
        write_missing = [s for s in write_scopes if s not in cur]

        if read_missing:
            missing_all.extend(read_missing)
        if write_missing:
            missing_all.extend(write_missing)

        results.append({
            "service": service,
            "read_missing":  read_missing,
            "write_missing": write_missing,
            "both_missing":  sorted(set(read_missing + write_missing)),
        })

    return results, sorted(set(missing_all))

# ===============================
# Génération d'URL de réauth
# ===============================

def generate_reauth_url(client_id: str, redirect_uri: str, scopes: list[str]) -> str:
    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "prompt": "consent"
    }
    return f"{base_url}?{urlencode(params)}"

# ===============================
# Endpoints utilisables avec userinfo.*
# ===============================

def oauth2_userinfo_endpoints() -> list[dict]:
    return [
        {
            "service": "Google OAuth2",
            "method": "GET",
            "url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "requires": ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
            "example": "curl -H 'Authorization: Bearer $ACCESS_TOKEN' https://www.googleapis.com/oauth2/v2/userinfo"
        },
        {
            "service": "Google OAuth2",
            "method": "GET",
            "url": "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$ACCESS_TOKEN",
            "requires": [],
            "example": "curl 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$ACCESS_TOKEN'"
        }
    ]