#!/usr/bin/env bash
# Self-test for the argv key scanner: no operational script may expand a token
# or key into curl argv. Moved here when the ElevenLabs script was parked; the
# scanner and its bite proofs are unchanged.
#
# Scans scripts/*.sh (operational scripts only, not test-*.sh) and fails on a
# `--header`/`-H` value that expands, or a curl line that names a credential and
# expands. Bite proofs run the scanner on hostile fixtures in a temp dir.
#
# Run: scripts/test-check-argv-keys.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

command -v python3 >/dev/null || { echo "FAIL: python3 required" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/auxesis-argv-keys-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Scans scripts/*.sh for key material on a command line: a `--header`/`-H`
# value that can expand (double-quoted or bare) and curl lines mentioning
# Authorization/xi-api-key/Bearer with a shell expansion.
cat > "$work/scan_argv.py" <<'PY'
import os
import re
import sys

HEADER_RE = re.compile(
    r"""(?:--header|-H)\s+(?P<q>['"])(?P<v>.*?)(?P=q)|(?:--header|-H)\s+(?P<bare>[^\s'"]+)"""
)
KEY_WORDS = re.compile(r"Authorization|xi-api-key|Bearer|AUX_KEY_[A-Z]")


def scan(path):
    findings = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for match in HEADER_RE.finditer(line):
                quote = match.group("q")
                value = (
                    match.group("v")
                    if match.group("v") is not None
                    else match.group("bare")
                )
                if value is None or quote == "'":
                    continue  # single quotes never expand
                if "$" in value or "`" in value:
                    findings.append(
                        "%s:%d: header value expands into argv" % (path, number)
                    )
            if (
                "curl" in line
                and KEY_WORDS.search(line)
                and "$" in line
                and "--config" not in line
            ):
                # `--config` carries the credential on stdin (never argv); a
                # header/user argument that expands is still caught above.
                findings.append(
                    "%s:%d: key material on a curl command line" % (path, number)
                )
    return findings


def main():
    findings = []
    for name in sorted(os.listdir(sys.argv[1])):
        # Operational scripts only: the test files embed hostile fixtures on
        # purpose and are exercised through the temp-dir bite proofs below.
        if name.endswith(".sh") and not name.startswith("test-"):
            findings.extend(scan(os.path.join(sys.argv[1], name)))
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
PY

if ! out="$(python3 "$work/scan_argv.py" "$repo_root/scripts")"; then
    fail "a script expands a key into argv: $out"
fi
[ -z "$out" ] || fail "scanner produced output on a clean tree: $out"

# Bite proof: the scanner must flag an argv-expanded bearer token.
mkdir -p "$work/hostile-scripts"
cat > "$work/hostile-scripts/auxd_check.sh" <<'SH'
#!/usr/bin/env bash
curl -H "Authorization: Bearer $AUX_KEY_AUXD" https://example.invalid/
SH
if out="$(python3 "$work/scan_argv.py" "$work/hostile-scripts")"; then
    fail "scanner accepted an argv-expanded bearer token"
fi
grep -q "header value expands" <<<"$out" || fail "scanner message missing: $out"
cat > "$work/hostile-scripts/auxd_check.sh" <<'SH'
#!/usr/bin/env bash
curl --config - < <(printf 'header = "Authorization: Bearer %s"\n' "$AUX_KEY_AUXD")
SH
if ! out="$(python3 "$work/scan_argv.py" "$work/hostile-scripts")"; then
    fail "the --config form was flagged: $out"
fi

echo "OK: argv key scanner self-test"
