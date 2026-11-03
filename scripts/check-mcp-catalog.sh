#!/usr/bin/env bash
# check-mcp-catalog.sh — validate catalog/mcp-servers.toml.
#
# Light, dependency-free gate over the MCP discovery catalogue:
#   * valid TOML;
#   * unique kebab-case ids and all required fields present;
#   * field values inside their enums ("unverified" is the explicit unknown);
#   * provenance URLs are https (endpoint is required when transport = http);
#   * tier = recommended only for official / public-body / vendor-first-party
#     servers that are read-only;
#   * a file-level catalog_version, and a stdio install pin that is either
#     complete (version, sha256, command, args, permissions) or absent:
#     a partial pin is a hole, so a partial entry is display-only.
#
# Uses python3 -I and the standard-library tomllib only. No network, no
# Keychain, no home directory access.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

catalog="${1:-catalog/mcp-servers.toml}"
packs="${2:-catalog/mcp-packs.toml}"

python3 -I - "$catalog" "$packs" <<'PY'
import re
import sys
import tomllib

path = sys.argv[1]
packs_path = sys.argv[2]
try:
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
except FileNotFoundError:
    print(f"check-mcp-catalog: missing file: {path}", file=sys.stderr)
    raise SystemExit(1)
except tomllib.TOMLDecodeError as err:
    print(f"check-mcp-catalog: invalid TOML in {path}: {err}", file=sys.stderr)
    raise SystemExit(1)

servers = data.get("server")
if not isinstance(servers, list) or not servers:
    print("check-mcp-catalog: expected at least one [[server]] entry", file=sys.stderr)
    raise SystemExit(1)

REQUIRED = [
    "id", "data_class", "name", "region", "category", "operator", "status", "repo_url",
    "transport", "auth", "license", "access", "evidence_url", "last_checked",
    "tier", "notes",
]
URL_FIELDS = ("repo_url", "evidence_url", "endpoint")

CATEGORIES = {
    "gov-data", "law", "tax-vat", "company-registry", "statistics", "geo",
    "weather", "transport", "finance-rates", "research", "payments",
    "accounting", "calendar", "storage", "notes-tasks", "comms", "crm",
    "other", "unverified",
}
STATUSES = {"official", "public-body", "vendor-first-party", "community", "unverified"}
TRANSPORTS = {"stdio", "http", "unverified"}
AUTHS = {"none", "api-key", "oauth", "account", "unverified"}
ACCESSES = {"read-only", "read-write", "unverified"}
TIERS = {"recommended", "candidate", "avoid"}
REGION_RE = re.compile(r"^[a-z]{2}$")
PACKS = {"freelance-fr", "freelance-eu", "travel", "research", "productivity", "public-data", "finance", "unassigned"}
VERIFIED = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CATALOG_VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}-\d+$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
TOOL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")
# A stdio install pin is all five or none: a partial pin is a hole, not data.
PIN_FIELDS = ("version", "sha256", "command", "args", "permissions")

errors = []
seen_ids = {}
counts = {"recommended": 0, "candidate": 0, "avoid": 0}
pinned = 0


def bad(condition, message):
    if condition:
        errors.append(message)


def check_pin(label, server, transport):
    """Return 1 for a complete stdio pin; record why a partial one is refused."""
    if not any(field in server for field in PIN_FIELDS):
        return 0
    if transport != "stdio":
        errors.append(f"{label}: pin fields are stdio-only, transport is {transport}")
        return 0
    for field in PIN_FIELDS:
        bad(field not in server, f"{label}: pinned stdio entry is missing '{field}'")
    version = server.get("version")
    bad(not isinstance(version, str) or not VERSION_RE.match(version), f"{label}: version must look like 1.2.3")
    sha = server.get("sha256")
    bad(not isinstance(sha, str) or not SHA256_RE.match(sha), f"{label}: sha256 must be 64 lowercase hex characters")
    command = server.get("command")
    bad(not isinstance(command, str) or not command.startswith("/") or any(ch.isspace() for ch in command), f"{label}: command must be one absolute path")
    args = server.get("args")
    bad(not isinstance(args, list) or any(not isinstance(arg, str) for arg in args), f"{label}: args must be a list of strings")
    permissions = server.get("permissions")
    if not isinstance(permissions, dict):
        errors.append(f"{label}: permissions must be a table")
        return 0
    bad(set(permissions) - {"tools", "network", "env"}, f"{label}: unknown permissions keys {sorted(set(permissions) - {'tools', 'network', 'env'})}")
    tools = permissions.get("tools")
    bad(not isinstance(tools, list) or not 1 <= len(tools) <= 32 or any(not isinstance(name, str) or not TOOL_RE.match(name) for name in tools), f"{label}: permissions.tools must list 1 to 32 tool names")
    bad(not isinstance(permissions.get("network"), bool), f"{label}: permissions.network must be a boolean")
    env = permissions.get("env")
    bad(not isinstance(env, list) or any(not isinstance(name, str) or not ENV_RE.match(name) for name in env), f"{label}: permissions.env must list env NAMES")
    return 0 if any(field not in server for field in PIN_FIELDS) else 1


catalog_version = data.get("catalog_version")
if not isinstance(catalog_version, str) or not CATALOG_VERSION_RE.match(catalog_version):
    errors.append("catalog_version must look like 2026.11.02-1")

for index, server in enumerate(servers, start=1):
    label = server.get("id") or f"entry #{index}"
    if not isinstance(server, dict):
        errors.append(f"{label}: entry is not a table")
        continue

    for field in REQUIRED:
        value = server.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label}: missing or empty required field '{field}'")
    if any(not isinstance(server.get(f), str) or not server.get(f).strip() for f in REQUIRED):
        continue

    sid = server["id"]
    if not ID_RE.match(sid):
        errors.append(f"{label}: id '{sid}' is not kebab-case")
    if sid in seen_ids:
        errors.append(f"{label}: duplicate id '{sid}' (also entry #{seen_ids[sid]})")
    else:
        seen_ids[sid] = index

    region = server["region"]
    if region not in ("global", "unverified") and not REGION_RE.match(region):
        errors.append(f"{label}: invalid region '{region}'")

    if server["category"] not in CATEGORIES:
        errors.append(f"{label}: invalid category '{server['category']}'")
    if server["status"] not in STATUSES:
        errors.append(f"{label}: invalid status '{server['status']}'")
    transport = server["transport"]
    if transport not in TRANSPORTS:
        errors.append(f"{label}: invalid transport '{transport}'")
    if server["auth"] not in AUTHS:
        errors.append(f"{label}: invalid auth '{server['auth']}'")
    if server["access"] not in ACCESSES:
        errors.append(f"{label}: invalid access '{server['access']}'")
    if server["data_class"] not in ("public", "sensitive"):
        errors.append(f"{label}: data_class must be 'public' or 'sensitive'")
    if server["tier"] not in TIERS:
        errors.append(f"{label}: invalid tier '{server['tier']}'")
    else:
        counts[server["tier"]] += 1

    if server["last_checked"] != "2026-10-09":
        errors.append(f"{label}: last_checked must be '2026-10-09'")
    use_cases = server.get("use_cases")
    if not isinstance(use_cases, list) or not 1 <= len(use_cases) <= 3 or any(not isinstance(v, str) or not v.strip() for v in use_cases):
        errors.append(f"{label}: use_cases must contain 1 to 3 non-empty strings")
    if server.get("pack") not in PACKS:
        errors.append(f"{label}: invalid pack '{server.get('pack')}'")
    verified = server.get("verified_working")
    if not (verified in ("unverified", "failed") or isinstance(verified, str) and VERIFIED.match(verified)):
        errors.append(f"{label}: verified_working must be a date, 'unverified' or 'failed'")
    tool_count = server.get("tool_count")
    if not (tool_count == "unverified" or isinstance(tool_count, int) and tool_count >= 0):
        errors.append(f"{label}: tool_count must be a non-negative integer or 'unverified'")

    pinned += check_pin(label, server, transport)

    if transport == "http" and not server.get("endpoint"):
        errors.append(f"{label}: transport is http but endpoint is missing")
    for field in URL_FIELDS:
        value = server.get(field)
        if value is None:
            continue
        if value == "unverified":
            continue
        if not value.startswith("https://"):
            errors.append(f"{label}: {field} must be an https URL or 'unverified', got '{value}'")

    if server["tier"] == "recommended":
        if server["status"] not in ("official", "public-body", "vendor-first-party"):
            errors.append(
                f"{label}: recommended requires an official/public-body/vendor-first-party status"
            )
        if server["access"] != "read-only":
            errors.append(f"{label}: recommended requires access = read-only")

try:
    with open(packs_path, "rb") as handle:
        pack_data = tomllib.load(handle)
except (FileNotFoundError, tomllib.TOMLDecodeError) as err:
    errors.append(f"invalid or missing packs file '{packs_path}': {err}")
    pack_data = {}
pack_entries = pack_data.get("pack", [])
if not isinstance(pack_entries, list) or not pack_entries:
    errors.append("packs file must contain [[pack]] entries")
else:
    pack_ids = set()
    by_id = {s.get("id"): s for s in servers if isinstance(s, dict)}
    for pack in pack_entries:
        pid = pack.get("id", "<unnamed>")
        if pid in pack_ids: errors.append(f"duplicate pack id '{pid}'")
        pack_ids.add(pid)
        for field in ("title_en", "title_fr", "description_en", "description_fr"):
            if not isinstance(pack.get(field), str) or not pack[field].strip():
                errors.append(f"pack {pid}: missing {field}")
        ids = pack.get("servers")
        if not isinstance(ids, list) or not 5 <= len(ids) <= 12:
            errors.append(f"pack {pid}: servers must contain 5 to 12 ordered ids")
            continue
        if len(set(ids)) != len(ids): errors.append(f"pack {pid}: duplicate server id")
        for sid in ids:
            server = by_id.get(sid)
            if server is None: errors.append(f"pack {pid}: unknown server id '{sid}'"); continue
            if server.get("tier") == "avoid": errors.append(f"pack {pid}: '{sid}' is avoid")
            if server.get("access") != "read-only": errors.append(f"pack {pid}: '{sid}' is not read-only")
            if server.get("data_class") != "public": errors.append(f"pack {pid}: '{sid}' is not public")
if not pack_ids.issubset(PACKS): errors.append(f"unknown pack ids: {sorted(pack_ids - PACKS)}")

if errors:
    for message in errors:
        print(f"check-mcp-catalog: {message}", file=sys.stderr)
    print(f"check-mcp-catalog: FAIL ({len(errors)} problem(s))", file=sys.stderr)
    raise SystemExit(1)

print(
    "check-mcp-catalog: OK — "
    f"{len(servers)} servers across {len(pack_entries)} packs "
    f"({counts['recommended']} recommended, {counts['candidate']} candidate, "
    f"{counts['avoid']} avoid; {pinned} pinned, {len(servers) - pinned} display-only) "
    f"in {path} and {packs_path}"
)
PY
