#!/usr/bin/env bash
# Fail if the owner's username or machine-specific temp paths are tracked by
# git. The username is read from the environment (or `id -un`) at run time and
# never stored in this file or anywhere else.
#
# Scope notes:
#   * scans the WHOLE tracked tree;
#   * every tracked file is scanned, QA reports included. They used to be
#     excluded while they were frozen; they are scrubbed now (owner data
#     replaced with placeholders), so an exclusion would only hide a
#     regression;
#   * runs from scripts/check-no-secrets.sh, so the pre-commit hook and CI
#     both enforce it;
#   * the username check only makes sense for a named owner account. CI
#     runners have generic accounts (`runner`, `root`, `ubuntu`, ...) and CI
#     cannot know the owner's username, so there it runs ONLY the fixed
#     machine-path patterns below — scanning for `runner` matches scheduler
#     code and QA logs, not personal data. The same skip applies to
#     any generic or very short local account name. The owner's username is
#     scrubbed from the whole tree, so the check passes on CI as well.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/guard.sh"  # Refuse a contradictory sandbox HOME

# Optional path argument: scan that directory instead of this repository's
# tracked tree. Without an argument the tracked tree is scanned, as before.
target="${1:-}"
if [[ -n "$target" ]]; then
    if [[ ! -d "$target" ]]; then
        echo "FAIL: not a directory: $target" >&2
        exit 2
    fi
    cd "$target"
    scope="the scanned tree"
else
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "FAIL: not inside a git work tree — refusing to report a clean scan" >&2
        exit 1
    fi
    cd "$(git rev-parse --show-toplevel)"
    scope="tracked files"
fi

# Scan the tree and print the hits. The exit status is the scanner's: 0 = a
# hit, 1 = no hit, anything else = the scan itself failed and proves nothing.
scan() {
    if [[ -n "$target" ]]; then
        grep -r -n -I -E "$1" --exclude-dir=.git . | sed -e 's|^\./||'
    else
        git grep -n -E "$1" -- . 2>/dev/null
    fi
}

# $USER first so the guard sees exactly what CI sets (`runner`); `id -un`
# covers environments that do not export the shell variable.
user="${USER:-$(id -un)}"
user_lc="$(printf '%s' "$user" | tr '[:upper:]' '[:lower:]')"
fail=0

# Known CI/container/shared account names. They are not a personal identity,
# and using one as a scan term only produces false positives.
generic_users=",runner,root,ubuntu,admin,administrator,user,vagrant,docker,builder,jenkins,circleci,travis,gitlab-runner,github-runner,github-actions,azureuser,ec2-user,cloud-user,packer,test,guest,nobody,"

# 1. The username as a standalone token (paths, prose, ls output columns).
#    Case-sensitive on purpose: the public author name in Cargo.toml is
#    deliberate metadata (audit B-21), not personal data.
scan_user=1
if [[ -n "${CI:-}${GITHUB_ACTIONS:-}${GITLAB_CI:-}${BUILDKITE:-}" ]]; then
    scan_user=0
elif (( ${#user} < 4 )); then
    scan_user=0
else
    case "$generic_users" in
        *",$user_lc,"*) scan_user=0 ;;
    esac
fi

if [[ "$scan_user" -eq 1 ]]; then
    # A `.` in a username is the only ERE metacharacter macOS allows; escape it
    # so `first.last` cannot match `firstXlast`.
    user_re="${user//./\\.}"
    rc=0
    hits="$(scan "(^|[^A-Za-z0-9_.-])${user_re}([^A-Za-z0-9_-]|$)")" || rc=$?
    if (( rc > 1 )); then
        echo "FAIL: the personal-data scan itself failed (exit $rc) — refusing to report a clean scan" >&2
        exit 2
    fi
    if [[ -n "$hits" ]]; then
        echo "FAIL: the machine username appears in $scope:"
        printf '%s\n' "$hits"
        fail=1
    fi
else
    echo "SKIP: machine username check (account '$user' is CI/generic or shorter than 4 chars); fixed machine-path checks still run"
fi

# 2. Machine-specific $TMPDIR paths (/var/folders/<hash>/<hash>). They must be
#    <tmp> in documents or $TMPDIR / ${TMPDIR:-/tmp} in scripts. This is the
#    fixed, username-independent list, so it also runs when check 1 is skipped.
rc=0
hits="$(scan '/(private/)?var/folders/[A-Za-z0-9_]+/[A-Za-z0-9_]+')" || rc=$?
if (( rc > 1 )); then
    echo "FAIL: the personal-data scan itself failed (exit $rc) — refusing to report a clean scan" >&2
    exit 2
fi
if [[ -n "$hits" ]]; then
    echo "FAIL: machine-specific /var/folders paths appear in $scope:"
    printf '%s\n' "$hits"
    fail=1
fi

if [[ "$fail" -eq 0 ]]; then
    echo "OK: no personal data tracked"
fi
exit "$fail"
