#!/usr/bin/env bash
# Self-test for .gitleaks.toml.
#
# gitleaks applies allowlist paths with MatchString. Every entry must therefore
# be a full repo-relative path anchored with ^...$ and have every dot escaped,
# so it cannot suppress a finding in a backup (`<path>.bak`), a prefixed file
# (`a<path>`) or the same suffix under another directory.
#
# This parses the TOML, derives the literal path from each pattern, and proves:
#   * the pattern is exactly ^<escaped literal>$ and the file exists;
#   * the pattern matches its own path;
#   * it matches no sibling variant and no other listed path.
#
# No gitleaks binary is needed. gate-fast.sh runs this.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"

command -v python3 >/dev/null 2>&1 || {
    echo "test-gitleaks-config: python3 is required to parse .gitleaks.toml" >&2
    exit 2
}
python3 -c 'import tomllib' 2>/dev/null || {
    echo "test-gitleaks-config: python3 3.11+ is required (tomllib)" >&2
    exit 2
}

exec python3 - "$root/.gitleaks.toml" "$root" <<'PY'
import pathlib
import re
import sys
import tomllib

config_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])

try:
    data = tomllib.loads(config_path.read_text())
except Exception as exc:
    sys.exit(f"test-gitleaks-config: FAIL: {config_path} is not valid TOML: {exc}")

allow = data.get("allowlist")
if not isinstance(allow, dict):
    sys.exit("test-gitleaks-config: FAIL: no [allowlist] table")
extra = set(allow) - {"description", "paths"}
if extra:
    sys.exit(
        f"test-gitleaks-config: FAIL: [allowlist] has non-path keys: {sorted(extra)}"
    )
raw_paths = allow.get("paths")
if not isinstance(raw_paths, list) or not raw_paths:
    sys.exit("test-gitleaks-config: FAIL: [allowlist].paths is empty")

patterns = []
literals = []
for raw in raw_paths:
    if not isinstance(raw, str):
        sys.exit(f"test-gitleaks-config: FAIL: non-string path: {raw!r}")
    if not (raw.startswith("^") and raw.endswith("$")):
        sys.exit(f"test-gitleaks-config: FAIL: path is not anchored ^...$: {raw}")
    body = raw[1:-1]
    literal = body.replace(r"\.", ".")
    if "\\" in literal:
        sys.exit(f"test-gitleaks-config: FAIL: unsupported escape in {raw}")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", literal):
        sys.exit(f"test-gitleaks-config: FAIL: unexpected character in {literal}")
    expected = "^" + literal.replace(".", r"\.") + "$"
    if raw != expected:
        sys.exit(
            "test-gitleaks-config: FAIL: pattern is not the escaped literal path\n"
            f"  pattern:  {raw}\n  expected: {expected}"
        )
    if not (root / literal).is_file():
        sys.exit(f"test-gitleaks-config: FAIL: allowlisted path does not exist: {literal}")
    patterns.append(raw)
    literals.append(literal)

if len(set(literals)) != len(literals):
    dupes = sorted({p for p in literals if literals.count(p) > 1})
    sys.exit(f"test-gitleaks-config: FAIL: duplicate paths: {dupes}")

for raw, literal in zip(patterns, literals):
    if not re.fullmatch(raw, literal):
        sys.exit(f"test-gitleaks-config: FAIL: {raw} does not match its own path")
    # A sibling must not be suppressed: backup, prefix, suffix, another
    # directory, and a subdirectory inserted into the path.
    variants = [
        literal + ".bak",
        "a" + literal,
        literal + "x",
        "x/" + literal,
        "sub/" + literal,
        "./" + literal,
        literal.replace("/", "/sub/", 1),
    ]
    for variant in variants:
        if re.fullmatch(raw, variant):
            sys.exit(
                f"test-gitleaks-config: FAIL: {raw} also matches sibling {variant}"
            )
    for other in literals:
        if other != literal and re.fullmatch(raw, other):
            sys.exit(f"test-gitleaks-config: FAIL: {raw} also matches {other}")

print(
    f"OK: .gitleaks.toml: {len(patterns)} anchored paths, "
    "each matches only its own fixture"
)
PY
