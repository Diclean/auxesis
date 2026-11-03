#!/usr/bin/env bash
# The CLT XCTest shim discovers test methods through the ObjC runtime. Keep
# every XCTestCase subclass visible to it by requiring @objcMembers.
set -euo pipefail

check_dir() {
    local tests_dir="$1" work list file count=0 result
    [[ -d "$tests_dir" ]] || { echo "swift-test-discovery: missing test directory: $tests_dir" >&2; return 1; }
    work="$(mktemp -d "${TMPDIR:-/tmp}/swift-test-discovery-check.XXXXXX")" || return 1
    list="$work/files"
    if ! find "$tests_dir" -type f -name '*.swift' -print0 > "$list"; then
        echo "swift-test-discovery: failed to scan $tests_dir" >&2
        rm -rf "$work"
        return 1
    fi
    : > "$work/declarations"
    while IFS= read -r -d '' file; do
        count=$((count + 1))
        if ! awk '
            function save_decl(    rest, base) {
                rest = header
                sub(/\{.*/, "", rest)
                base = ""
                if (rest ~ /:/) {
                    sub(/^[^:]*:/, "", rest)
                    sub(/,.*/, "", rest)
                    sub(/^[[:space:]]*/, "", rest)
                    sub(/[^A-Za-z0-9_].*$/, "", rest)
                    base = rest
                }
                printf "%s\t%s\t%d\t%s:%d\n", class_name, base, annotated, FILENAME, class_line
                collecting = 0
                header = ""
            }
            {
                line = $0
                sub(/\/\/.*$/, "", line)
                if (!collecting) {
                    if (line ~ /(^|[[:space:]])class[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
                        rest = line
                        sub(/^.*class[[:space:]]+/, "", rest)
                        class_name = rest
                        sub(/[^A-Za-z0-9_].*$/, "", class_name)
                        header = line
                        sub(/^.*class[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/, "", header)
                        annotated = pending_objc || line ~ /@objcMembers/
                        class_line = FNR
                        pending_objc = 0
                        collecting = 1
                    } else if (line ~ /@objcMembers/) {
                        pending_objc = 1
                    } else if (line !~ /^[[:space:]]*$/ && line !~ /^[[:space:]]*@/ ) {
                        pending_objc = 0
                    }
                } else {
                    header = header " " line
                }
                if (collecting && header ~ /\{/) save_decl()
            }
            END { if (collecting) save_decl() }
        ' "$file" >> "$work/declarations"; then
            echo "swift-test-discovery: failed to read $file" >&2
            rm -rf "$work"
            return 1
        fi
    done < "$list"
    if (( count == 0 )); then
        echo "swift-test-discovery: no Swift test files in $tests_dir" >&2
        rm -rf "$work"
        return 1
    fi
    if ! awk -F '\t' '
        { name[NR]=$1; base[NR]=$2; annotated[NR]=$3; where[NR]=$4; if ($2 == "XCTestCase") test[$1]=1 }
        END {
            changed=1
            while (changed) {
                changed=0
                for (i=1; i<=NR; i++) if (test[base[i]] && !test[name[i]]) { test[name[i]]=1; changed=1 }
            }
            total=0
            for (i=1; i<=NR; i++) if (test[name[i]]) {
                total++
                if (!annotated[i]) { printf "%s: XCTestCase subclass needs @objcMembers\n", where[i]; bad=1 }
            }
            if (!total) { print "swift-test-discovery: no XCTestCase subclasses found" > "/dev/stderr"; exit 1 }
            exit bad
        }
    ' "$work/declarations"; then
        rm -rf "$work"
        return 1
    fi
    rm -rf "$work"
}

if [[ "${1:-}" == "--self-test" ]]; then
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/swift-test-discovery.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/good" "$tmp/bad" "$tmp/non-test" "$tmp/empty"
    cat > "$tmp/good/Good.swift" <<'FIXTURE'
// attributes may be separated from the declaration
@MainActor

// and comments or blank lines do not break the annotation
@objcMembers
final class AnnotatedAbove
    : XCTestCase
{
}
@MainActor @objcMembers final class AnnotatedInline: XCTestCase {}
class OrdinaryModel: NSObject {}
FIXTURE
    cat > "$tmp/bad/Bad.swift" <<'FIXTURE'
private final class InvisibleOne: XCTestCase {}
@MainActor
open class InvisibleTwo
    : XCTestCase
{}
@objcMembers class BaseTestCase: XCTestCase {}
class Derived: BaseTestCase {}
class Grandchild
    : Derived
{}
FIXTURE
    cat > "$tmp/non-test/OnlyModels.swift" <<'FIXTURE'
class Model: NSObject {}
struct Value {}
FIXTURE
    check_dir "$tmp/good" || { echo "swift-test-discovery self-test: FAIL (good fixtures rejected)" >&2; exit 1; }
    if check_dir "$tmp/bad"; then echo "swift-test-discovery self-test: FAIL (bad fixtures accepted)" >&2; exit 1; fi
    if check_dir "$tmp/non-test"; then echo "swift-test-discovery self-test: FAIL (zero subclasses accepted)" >&2; exit 1; fi
    if check_dir "$tmp/empty"; then echo "swift-test-discovery self-test: FAIL (empty directory accepted)" >&2; exit 1; fi
    if check_dir "$tmp/missing"; then echo "swift-test-discovery self-test: FAIL (missing directory accepted)" >&2; exit 1; fi
    mkdir "$tmp/bin"
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/find"
    chmod +x "$tmp/bin/find"
    if PATH="$tmp/bin:$PATH" check_dir "$tmp/good"; then echo "swift-test-discovery self-test: FAIL (find error accepted)" >&2; exit 1; fi
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/awk"
    chmod +x "$tmp/bin/awk"
    if PATH="$tmp/bin:$PATH" check_dir "$tmp/good"; then echo "swift-test-discovery self-test: FAIL (read error accepted)" >&2; exit 1; fi
    echo "swift-test-discovery self-test: PASS"
    exit 0
fi

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [--self-test|TESTS_DIR]" >&2
    exit 2
fi
tests_dir="${1:-$(git rev-parse --show-toplevel)/apps/auxesis-mac/Tests}"
if ! check_dir "$tests_dir"; then exit 1; fi
echo "swift-test-discovery: OK"
