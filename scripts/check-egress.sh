#!/usr/bin/env bash
# Egress contract check.
#
# Every reqwest client built in production code must be documented in
# docs/egress.md and listed in its machine-readable allowlist. The allowlist is
# per constructor: one entry is `file::function`, the Rust function that holds
# the constructor. A second client added to an allowlisted file is therefore
# flagged too, not waved through by its file name.
#
# Mail does not use reqwest: it opens raw TCP sockets. The same rule applies to
# `TcpStream::connect`, through a second allowlist block
# (`egress-raw-sockets`) in the same document. Unit-test code is skipped (a
# `tests.rs`, a `tests/` path, a `#[cfg(test)] mod …;`, or a `#[cfg(test)] { … }`
# region), because a test double may dial loopback freely.
#
# The check is static and offline: it greps source only.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

docs="docs/egress.md"

if [[ ! -f "$docs" ]]; then
    echo "check-egress: FATAL: $docs is missing" >&2
    exit 1
fi

allowlist="$(mktemp)"
raw_allowlist="$(mktemp)"
trap 'rm -f "$allowlist" "$raw_allowlist"' EXIT

# Extract an allowlist fenced between HTML markers. A missing raw block is an
# empty allowlist, so a raw socket with no documented entry still fails.
extract_block() {
    local start="$1" end="$2"
    awk -v start="$start" -v end="$end" '
        index($0, start) { inblock = 1; next }
        index($0, end)   { inblock = 0; next }
        inblock { print }
    ' "$docs" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$' || true
}

extract_block "<!-- egress-allowlist:start -->" "<!-- egress-allowlist:end -->" >"$allowlist"

if [[ ! -s "$allowlist" ]]; then
    echo "check-egress: FATAL: no allowlist block found in $docs" >&2
    exit 1
fi

extract_block "<!-- egress-raw-sockets:start -->" "<!-- egress-raw-sockets:end -->" >"$raw_allowlist"

# The Rust function that encloses `file:line`: the last `fn NAME` declared at
# or before that line. A constructor outside any function is `<top-level>`.
enclosing_fn() {
    awk -v target="$2" '
        NR > target { exit }
        /^[[:space:]]*\/\// { next }
        match($0, /(^|[^A-Za-z0-9_])fn[[:space:]]+[A-Za-z0-9_]+/) {
            name = substr($0, RSTART, RLENGTH)
            sub(/^.*fn[[:space:]]+/, "", name)
        }
        END { print (name == "" ? "<top-level>" : name) }
    ' "$1"
}

# True when `file` is only compiled for tests: a `tests.rs`, a `tests/` path,
# or a module declared by a `#[cfg(test)]`/`#[cfg(any(test, …))] mod <stem>;`
# in the file's *own parent module*. A same-stem `mod` somewhere else in the
# tree must not exempt this file (P2-4b).
is_test_only_file() {
    local file="$1" base="${1##*/}" stem dir declaration decl_lineno prev parent
    [[ "$base" == "tests.rs" ]] && return 0
    [[ "$file" == */tests/* ]] && return 0
    stem="${base%.rs}"
    dir="${file%/*}"
    local -a parents=("$dir.rs" "$dir/mod.rs")
    # A crate root declares its own top-level modules in lib.rs / main.rs.
    if [[ "${dir##*/}" == "src" ]]; then
        parents+=("$dir/lib.rs" "$dir/main.rs")
    fi
    for parent in "${parents[@]}"; do
        [[ -f "$parent" ]] || continue
        while IFS= read -r declaration; do
            [[ -z "$declaration" ]] && continue
            decl_lineno="${declaration#*:}"
            decl_lineno="${decl_lineno%%:*}"
            prev="$(awk -v target="$decl_lineno" '
                NR >= target { exit }
                /^[[:space:]]*\/\// { next }
                /^[[:space:]]*$/ { next }
                { last = $0 }
                END { print last }
            ' "$parent")"
            case "$prev" in
                *"cfg(test"*|*"cfg(any(test"*|*"cfg(all(test"*) return 0 ;;
            esac
        done < <(git grep -nE "^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+${stem}[[:space:]]*;" -- "$parent" || true)
    done
    return 1
}

# True when `line` sits inside a `#[cfg(test)] { … }` region of `file`. Only
# an actual attribute line arms the region: a commented-out `#[cfg(test)]`
# does not exempt the code after it (P2-4a).
is_inline_test() {
    [[ "$(awk -v target="$2" '
        NR > target { exit }
        /^[[:space:]]*#\[cfg\(test\)\]/ { armed = 1; depth = 0; started = 0 }
        armed {
            opens = gsub(/\{/, "{")
            closes = gsub(/\}/, "}")
            depth += opens - closes
            if (opens > 0) started = 1
            if (started && depth <= 0) { armed = 0; started = 0 }
            else if (!started && /;/) { armed = 0 }
        }
        NR == target { if (armed) print "test" }
    ' "$1")" == "test" ]]
}

is_test_code() {
    is_test_only_file "$1" && return 0
    is_inline_test "$1" "$2"
}

# Check every match of `pattern` in production source against `list`. Skips
# test code when `skip_tests` is 1, and (when `file_contains` is non-empty)
# only keeps matches in a file that also names that literal (P2-4c).
# Writes the kept-match count to `count`.
count=0
check_pattern() {
    local label="$1" pattern="$2" list="$3" skip_tests="$4" file_contains="${5:-}" found=0
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        local file="${match%%:*}"
        local rest="${match#*:}"
        local line="${rest%%:*}"
        if [[ "$skip_tests" == "1" ]] && is_test_code "$file" "$line"; then
            continue
        fi
        if [[ -n "$file_contains" ]] && ! grep -qF "$file_contains" "$file" 2>/dev/null; then
            continue
        fi
        found=$((found + 1))
        local function
        function="$(enclosing_fn "$file" "$line")"
        if ! grep -qxF "$file::$function" "$list"; then
            echo "check-egress: unlisted ${label} at ${match} (function ${function})" >&2
            failed=1
        fi
    done < <(git grep --untracked -nE "$pattern" -- 'crates/**/src/**' 'apps/**/src/**' || true)
    count="$found"
}

# A reqwest constructor is `reqwest::Client::builder(` / `reqwest::Client::new(`
# or a bare `Client::builder(` / `Client::new(` where `Client` is the imported
# reqwest type. A qualified path such as `async_imap::Client::new(` is not a
# reqwest constructor and is deliberately not matched.
reqwest_pattern='(reqwest::Client::(builder|new)\(|(^|[^A-Za-z0-9_:])Client::(builder|new)\()'

# Raw sockets, P2-4c: a `TcpStream`/`TcpSocket` connect (a plain `TcpStream::
# connect` used to be the only spelling), an aliased type (`use … as T;
# T::connect(`), a `TcpSocket` value's `.connect(` (its `bind`/`listen` are not
# egress, so this one is gated on the file naming `TcpSocket`), and a `::`
# split before `connect(` on the next line (see `check_split_connect`).
raw_pattern='(^|[^A-Za-z0-9_])(TcpStream|TcpSocket)::(connect|connect_timeout)\('
alias_pattern='(^|[^A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*::connect(_timeout)?\('
socket_method_pattern='\.connect(_timeout)?\('

# A `…::` split before `connect(` on the next line is still a raw dial.
check_split_connect() {
    local list="$1" found=0 match file rest line next function
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        file="${match%%:*}"
        rest="${match#*:}"
        line="${rest%%:*}"
        next="$(awk -v target="$((line + 1))" 'NR == target { print; exit }' "$file")"
        [[ "$next" =~ ^[[:space:]]*(connect|connect_timeout)[[:space:]]*\( ]] || continue
        if is_test_code "$file" "$line"; then
            continue
        fi
        found=$((found + 1))
        function="$(enclosing_fn "$file" "$line")"
        if ! grep -qxF "$file::$function" "$list"; then
            echo "check-egress: unlisted raw socket at ${match} (function ${function})" >&2
            failed=1
        fi
    done < <(git grep --untracked -nE '::[[:space:]]*$' -- 'crates/**/src/**' 'apps/**/src/**' || true)
    count="$found"
}

failed=0
check_pattern "reqwest client" "$reqwest_pattern" "$allowlist" 0
found="$count"
check_pattern "raw socket" "$raw_pattern" "$raw_allowlist" 1
raw_found="$count"
check_pattern "raw socket" "$alias_pattern" "$raw_allowlist" 1 "TcpStream"
raw_found=$((raw_found + count))
check_pattern "raw socket" "$alias_pattern" "$raw_allowlist" 1 "TcpSocket"
raw_found=$((raw_found + count))
check_pattern "raw socket" "$socket_method_pattern" "$raw_allowlist" 1 "TcpSocket"
raw_found=$((raw_found + count))
check_split_connect "$raw_allowlist"
raw_found=$((raw_found + count))

if [[ "$failed" -ne 0 ]]; then
    echo "check-egress: FAIL — add its file::function to docs/egress.md (row + allowlist) or remove the egress point." >&2
    exit 1
fi

# P2-5: `aux-mail/test-support` (the `Dialer::with_client_config` seam) may be
# enabled only by aux-mail's own dev-dependency self-reference. Any other
# Cargo.toml naming the feature would put that seam in a production build.
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    [[ "${hit%%:*}" == "crates/aux-mail/Cargo.toml" ]] && continue
    echo "check-egress: FATAL: aux-mail/test-support enabled outside its dev-dependencies at $hit" >&2
    exit 1
done < <(git grep -n 'test-support' -- '**/Cargo.toml' 'Cargo.toml' || true)

constructors=$(grep -c . "$allowlist" || true)
raw_constructors=$(grep -c . "$raw_allowlist" || true)
echo "check-egress: OK — ${found} reqwest constructor(s) and ${raw_found} raw socket(s); ${constructors} + ${raw_constructors} allowlisted file::function entr(y/ies)."
