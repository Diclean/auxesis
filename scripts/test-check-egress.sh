#!/usr/bin/env bash
# Self-test for scripts/check-egress.sh. Both allowlists are per constructor
# (`file::function`), so a second client (reqwest or raw) added to an
# allowlisted file must fail the check. Runs in a throwaway git repository.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
# A second throwaway tree, deliberately NOT inside the git repository in $work, for
# the fail-closed cases: a copy of kernel/ that cannot be scanned must not pass.
nogit="$(mktemp -d)"
trap 'rm -rf "$work" "$nogit"' EXIT

mkdir -p "$work/scripts" "$work/docs" "$work/crates/demo/src"
cp "$root/scripts/check-egress.sh" "$work/scripts/check-egress.sh"

write_docs() {
    cat >"$work/docs/egress.md" <<DOC
<!-- egress-allowlist:start -->
$1
<!-- egress-allowlist:end -->
<!-- egress-raw-sockets:start -->
$2
<!-- egress-raw-sockets:end -->
DOC
}

write_docs "crates/demo/src/lib.rs::build" ""

cat >"$work/crates/demo/src/lib.rs" <<'RS'
fn build() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}
RS

git -C "$work" init -q
git -C "$work" add -A

# The check resolves its repository from the working directory, so it must
# run from inside the throwaway repository, never from this worktree.
run_check() {
    (cd "$work" && bash "$work/scripts/check-egress.sh")
}

# The app repo vendors the kernel, so a present kernel directory must retain
# its own egress gate. A standalone copy with no kernel directory is allowed.
mkdir -p "$work/kernel"
if run_check >"$work/missing-kernel-script.log" 2>&1; then
    echo "test-check-egress: FAIL — kernel/ without its egress script passed" >&2
    exit 1
fi
if ! grep -qF 'kernel/ exists but kernel/scripts/check-egress.sh is missing' "$work/missing-kernel-script.log"; then
    echo "test-check-egress: FAIL — missing kernel egress script had no clear error" >&2
    exit 1
fi
rmdir "$work/kernel"

# 1. The one allowlisted reqwest constructor passes.
run_check >/dev/null 2>&1 || {
    echo "test-check-egress: FAIL — the allowlisted constructor was refused" >&2
    exit 1
}

# 2. A second reqwest client in the same allowlisted file, in another function, fails.
cat >>"$work/crates/demo/src/lib.rs" <<'RS'

fn second() -> reqwest::Client {
    reqwest::Client::new()
}
RS
git -C "$work" add -A
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a new reqwest client in an allowlisted file passed" >&2
    exit 1
fi

# 3. Listing the new function makes it pass again.
write_docs "crates/demo/src/lib.rs::build
crates/demo/src/lib.rs::second" ""
git -C "$work" add -A
run_check >/dev/null 2>&1 || {
    echo "test-check-egress: FAIL — a listed function was still refused" >&2
    exit 1
}

# 4. A raw socket with no raw-sockets allowlist fails.
cat >>"$work/crates/demo/src/lib.rs" <<'RS'

fn dial() {
    let _ = std::net::TcpStream::connect(("127.0.0.1", 1));
}
RS
git -C "$work" add -A
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — an unlisted raw socket passed" >&2
    exit 1
fi

# 5. Listing the raw function makes it pass.
write_docs "crates/demo/src/lib.rs::build
crates/demo/src/lib.rs::second" "crates/demo/src/lib.rs::dial"
git -C "$work" add -A
run_check >/dev/null 2>&1 || {
    echo "test-check-egress: FAIL — a listed raw socket was still refused" >&2
    exit 1
}

# 6. A second raw socket in another function fails.
cat >>"$work/crates/demo/src/lib.rs" <<'RS'

fn dial_again() {
    let _ = std::net::TcpStream::connect(("127.0.0.1", 2));
}
RS
git -C "$work" add -A
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a second raw socket in an allowlisted file passed" >&2
    exit 1
fi

# 6b. Listing the second raw socket restores a clean baseline for the
# hole-by-hole cases below.
reqwest_list="crates/demo/src/lib.rs::build
crates/demo/src/lib.rs::second"
raw_list="crates/demo/src/lib.rs::dial
crates/demo/src/lib.rs::dial_again"
write_docs "$reqwest_list" "$raw_list"
git -C "$work" add -A
run_check >/dev/null 2>&1 || {
    echo "test-check-egress: FAIL — the listed raw baseline was refused" >&2
    exit 1
}

allow_raw() {
    raw_list="$raw_list
$1"
    write_docs "$reqwest_list" "$raw_list"
    git -C "$work" add -A
    run_check >/dev/null 2>&1 || {
        echo "test-check-egress: FAIL — allowlisting $1 did not pass" >&2
        exit 1
    }
}

write_probe() {
    cat >"$work/crates/demo/src/$1"
    git -C "$work" add -A
}

# 7. (a) A commented-out `#[cfg(test)]` must not exempt the code after it.
write_probe comment_armed.rs <<'RS'
// #[cfg(test)]
fn comment_armed_dial() {
    let _ = std::net::TcpStream::connect(("127.0.0.1", 3));
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a commented cfg(test) exempted a raw socket" >&2
    exit 1
fi
allow_raw "crates/demo/src/comment_armed.rs::comment_armed_dial"

# 8. (b) A same-stem `#[cfg(test)] mod other;` in a *different* module must
# not exempt crates/demo/src/other.rs.
cat >>"$work/crates/demo/src/lib.rs" <<'RS'

pub mod helper;
pub mod other;
RS
write_probe helper.rs <<'RS'
#[cfg(test)]
mod other;
RS
write_probe other.rs <<'RS'
pub fn other_dial() {
    let _ = std::net::TcpStream::connect(("127.0.0.1", 5));
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a same-stem cfg(test) mod exempted a production file" >&2
    exit 1
fi
allow_raw "crates/demo/src/other.rs::other_dial"

# 9. (c1) `TcpStream::connect_timeout(` is a raw socket.
write_probe timeout_dial.rs <<'RS'
pub fn timeout_dial(addr: std::net::SocketAddr) {
    let _ = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1));
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — TcpStream::connect_timeout passed" >&2
    exit 1
fi
allow_raw "crates/demo/src/timeout_dial.rs::timeout_dial"

# 10. (c2) A `TcpSocket` value's `.connect(` is a raw socket.
write_probe socket_dial.rs <<'RS'
pub async fn socket_dial(addr: std::net::SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    let _ = socket.connect(addr).await;
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a TcpSocket .connect passed" >&2
    exit 1
fi
allow_raw "crates/demo/src/socket_dial.rs::socket_dial"

# 11. (c3) An aliased raw type (`use … as T; T::connect(`) is a raw socket.
write_probe alias_dial.rs <<'RS'
use std::net::TcpStream as T;
pub fn alias_dial(addr: std::net::SocketAddr) {
    let _ = T::connect(addr);
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — an aliased T::connect passed" >&2
    exit 1
fi
allow_raw "crates/demo/src/alias_dial.rs::alias_dial"

# 12. (c4) A `::` split before `connect(` on the next line is a raw socket.
write_probe split_dial.rs <<'RS'
pub fn split_dial(addr: std::net::SocketAddr) {
    let _ = std::net::TcpStream::
        connect(addr);
}
RS
if run_check >/dev/null 2>&1; then
    echo "test-check-egress: FAIL — a split ::connect passed" >&2
    exit 1
fi
allow_raw "crates/demo/src/split_dial.rs::split_dial"

# 13. The kernel check fails CLOSED outside a git work tree. A copy of kernel/
# that cannot be scanned once printed "OK — 0 client constructor(s)" and exited 0,
# so a planted client passed the gate for free. It must be an error now.
mkdir -p "$nogit/scripts" "$nogit/docs" "$nogit/crates/demo/src"
cp "$root/kernel/scripts/check-egress.sh" "$nogit/scripts/check-egress.sh"
# The allowlist deliberately does not name `build`, so the planted client below
# is unlisted whenever the scan really happens.
cat >"$nogit/docs/egress.md" <<'DOC'
<!-- egress-allowlist:start -->
crates/demo/src/other.rs::nothing_here
<!-- egress-allowlist:end -->
DOC
cat >"$nogit/crates/demo/src/lib.rs" <<'RS'
fn build() -> reqwest::Client {
    reqwest::Client::new()
}
RS

if (cd "$nogit" && bash "$nogit/scripts/check-egress.sh") >"$nogit/nogit.log" 2>&1; then
    echo "test-check-egress: FAIL — a non-git copy passed the kernel egress check" >&2
    exit 1
fi
if ! grep -qF 'is not a git work tree' "$nogit/nogit.log"; then
    echo "test-check-egress: FAIL — a non-git copy had no clear error" >&2
    sed -n '1,5p' "$nogit/nogit.log" >&2
    exit 1
fi

# 14. The same copy, as a git repository, reports the planted client — so the
# case above fails on the missing work tree, not on a broken fixture — and passes
# once the function is listed.
git -C "$nogit" init -q
git -C "$nogit" add -A
if (cd "$nogit" && bash "$nogit/scripts/check-egress.sh") >"$nogit/git-unlisted.log" 2>&1; then
    echo "test-check-egress: FAIL — a planted kernel client passed once git was present" >&2
    exit 1
fi
if ! grep -qF 'unlisted reqwest client' "$nogit/git-unlisted.log"; then
    echo "test-check-egress: FAIL — the planted kernel client was not reported" >&2
    sed -n '1,5p' "$nogit/git-unlisted.log" >&2
    exit 1
fi
cat >"$nogit/docs/egress.md" <<'DOC'
<!-- egress-allowlist:start -->
crates/demo/src/lib.rs::build
<!-- egress-allowlist:end -->
DOC
git -C "$nogit" add -A
(cd "$nogit" && bash "$nogit/scripts/check-egress.sh") >/dev/null 2>&1 || {
    echo "test-check-egress: FAIL — the listed kernel constructor was refused" >&2
    exit 1
}

# 15. A scannable repository with no client at all is also a failure: an empty
# file list is a broken scan, not a clean tree.
empty="$nogit/empty"
mkdir -p "$empty/scripts" "$empty/docs" "$empty/crates/demo/src"
cp "$root/kernel/scripts/check-egress.sh" "$empty/scripts/check-egress.sh"
cp "$nogit/docs/egress.md" "$empty/docs/egress.md"
echo 'pub fn no_clients() -> u8 { 7 }' >"$empty/crates/demo/src/lib.rs"
git -C "$empty" init -q
git -C "$empty" add -A
if (cd "$empty" && bash "$empty/scripts/check-egress.sh") >"$empty/empty.log" 2>&1; then
    echo "test-check-egress: FAIL — an empty file list passed as a clean scan" >&2
    exit 1
fi
if ! grep -qF 'no client constructor found' "$empty/empty.log"; then
    echo "test-check-egress: FAIL — an empty scan had no clear error" >&2
    exit 1
fi

echo "test-check-egress: OK — per-constructor allowlists flag new reqwest and raw clients, the cfg(test)/stem exemptions are tight, every raw spelling is caught, and the kernel check fails closed when it cannot scan."
