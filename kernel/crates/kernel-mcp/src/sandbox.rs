//! macOS Seatbelt profile for a mounted stdio extension.
//!
//! An extension runs under `sandbox-exec` with a profile generated from its
//! catalog entry. The profile is deny-by-default and deliberately narrow:
//!
//! - **exec**: the extension's own install dir (read-only) and the exact
//!   runtime interpreter binaries the entry names — never a runtime
//!   *directory*, and never the extension's `work/` data dir, which is denied
//!   after the install-dir allow (rules are last-match-wins);
//! - **read**: the install dir, the runtime paths and the system libraries a
//!   runtime needs to start (dyld shared cache, `/usr/lib`, frameworks, TLS
//!   certs), plus the root directory literal dyld needs;
//! - **metadata**: only the allowed trees and the literal path components that
//!   lead to them. A global `file-read-metadata` would leak the existence,
//!   size and mtime of *any* file, including the owner's `~`;
//! - **write**: the extension's own `work/` dir only — never its install dir,
//!   never another extension, never the Auxesis home (deny default covers it);
//! - **process-info**: denied globally and allowed back for `self` only, so a
//!   child cannot read another process's argv/env through `sysctl`
//!   `KERN_PROCARGS2` or `proc_pidpath`;
//! - **file-map-executable**: denied on `work/`, so a dylib dropped there
//!   cannot be `dlopen`ed even though the tree is readable;
//! - **iokit**: `iokit-get-properties` is denied, so hardware identifiers such
//!   as `IOPlatformSerialNumber` stay unreadable;
//! - **network**: with `proxy_port = None` the profile carries **no** network
//!   rule at all, so `(deny default)` denies every socket, loopback included.
//!   With `proxy_port = Some(p)` it allows **TCP** outbound traffic to the
//!   IPv4 loopback address on `p` only (`tcp4`, so `::1` and UDP stay denied)
//!   — the egress proxy (`kernel-net::proxy`) enforces the entry's host
//!   allowlist from there. Seatbelt cannot filter by host name, so this one
//!   loopback port is the whole network surface.
//!
//! Paths are quoted as Scheme strings with backslashes and quotes escaped, and
//! control characters dropped, so a path can never shape the profile. A
//! dropped character makes the rule match no real path, which fails closed.
//! The kernel matches the *canonical* path, so callers pass canonical dirs.
//!
//! # Accepted limitations
//!
//! - `com.apple.system.opendirectoryd.libinfo` is allowed for Foundation/dyld
//!   startup. It lets a child enumerate local user and group directory records
//!   (names, uids, home paths) through opendirectoryd. No file contents or
//!   credentials are exposed, and the runtime cannot start without it, so this
//!   is accepted.
//! - The installer (app side) must refuse symlinks and hardlinks inside an
//!   extension archive before extraction (implemented in the app WO-13b). The
//!   sandbox trusts `install_dir` to hold the vetted tree; a link that escaped
//!   it would otherwise let a path outside the install tree be read or
//!   executed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// System directories a runtime reads to start: dyld, the C++/Foundation
/// libraries, the framework bundles and the TLS roots.
///
/// The dyld shared cache lives under the Preboot Cryptexes volume on current
/// macOS; without read access to it every child dies in dyld before `main`.
const SYSTEM_READ_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/System/Library",
    "/System/Library/dyld",
    "/System/Volumes/Preboot/Cryptexes",
    "/System/Cryptexes",
    "/Library/Apple",
    "/private/var/db/dyld",
    "/private/etc/ssl",
];

/// Device nodes a runtime opens: the null/random sinks and the three standard
/// streams.
const SYSTEM_READ_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
];

/// Mach services common runtimes look up while starting (CoreFoundation's
/// preferences and logging daemons). Nothing here exposes owner data.
const MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.cfprefsd.agent",
    "com.apple.system.logger",
    "com.apple.logd",
];

/// What one extension is allowed to touch, from its catalog entry.
///
/// `install_dir` is the `~/.auxesis/extensions/<name>@<version>/` tree
/// (read + exec, never write), `work_dir` is its `work/` subdirectory (the
/// only writable place, never executable) and `runtime_read_paths` are the
/// interpreter/system paths the entry's `command` needs. `proxy_port` is the
/// egress proxy's loopback port, or `None` for `network = []`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The extension's install dir: read and exec, never write.
    pub install_dir: PathBuf,
    /// The extension's own workspace: the only writable place, never exec.
    pub work_dir: PathBuf,
    /// Runtime paths (node/python/...) the extension may read and execute.
    /// Exec is granted on the exact path, never on its parent directory.
    pub runtime_read_paths: Vec<PathBuf>,
    /// The egress proxy's loopback port, or `None` when the entry declares
    /// `network = []` (no network rule at all).
    pub proxy_port: Option<u16>,
}

/// Build the deny-by-default Seatbelt profile for one extension.
///
/// Rules are ordered last-match-wins; the deny is the first line and every
/// allow is scoped, so a path that fails to escape can only narrow access. The
/// one deliberate deny-after-allow is `work/` under the install dir: the
/// install tree is executable, the extension's own data dir is not.
pub fn seatbelt_profile(spec: &SandboxSpec) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n(allow process-fork)\n");

    // Metadata is stat(), not readdir(): scoping it to the allowed trees and
    // their literal path components keeps `stat ~/.ssh/known_hosts` denied
    // while dyld can still traverse to the libraries it loads.
    profile.push_str("(allow file-read-metadata");
    for path in metadata_literals(spec) {
        profile.push_str(&format!(" (literal \"{path}\")"));
    }
    profile.push_str(")\n");

    // Exec: the exact runtime interpreters and the install dir. The work dir
    // is denied last, so a binary copied there never runs even though it sits
    // under the install tree.
    profile.push_str("(allow process-exec*");
    for path in &spec.runtime_read_paths {
        profile.push_str(&format!(" (literal \"{}\")", scheme_string(path)));
    }
    profile.push_str(&format!(
        " (subpath \"{}\"))\n",
        scheme_string(&spec.install_dir)
    ));
    profile.push_str(&format!(
        "(deny process-exec* (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    profile.push_str("(allow file-read*");
    // dyld opens the root directory itself; without this every child aborts.
    profile.push_str(" (literal \"/\")");
    profile.push_str(&format!(
        " (subpath \"{}\")",
        scheme_string(&spec.install_dir)
    ));
    profile.push_str(&format!(" (subpath \"{}\")", scheme_string(&spec.work_dir)));
    for path in &spec.runtime_read_paths {
        profile.push_str(&format!(" (subpath \"{}\")", scheme_string(path)));
    }
    for path in SYSTEM_READ_DIRS {
        profile.push_str(&format!(" (subpath \"{path}\")"));
    }
    for file in SYSTEM_READ_FILES {
        profile.push_str(&format!(" (literal \"{file}\")"));
    }
    profile.push_str(")\n");

    profile.push_str("(allow mach-lookup");
    for service in MACH_SERVICES {
        profile.push_str(&format!(" (global-name \"{service}\")"));
    }
    profile.push_str(")\n");

    // The only writable tree. The install dir is deliberately absent, so the
    // extension cannot rewrite its own code or its pinned tools.
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    if let Some(port) = spec.proxy_port {
        // `tcp4` pins the rule to TCP on 127.0.0.1: `localhost` would also
        // open ::1, and a bare `ip4` would also allow UDP.
        profile.push_str(&format!(
            "(allow network-outbound (remote tcp4 \"localhost:{port}\"))\n"
        ));
    }

    // Process introspection is denied globally and allowed back for self only
    // (last-match-wins). Without this a child reads any same-uid process's
    // argv/env through `sysctl KERN_PROCARGS2` and `proc_pidpath`.
    profile.push_str("(deny process-info*)\n");
    profile.push_str("(allow process-info* (target self))\n");

    // A dylib dropped into the writable data dir must not be mapped for
    // execution: read access alone would let `dlopen` run it.
    profile.push_str(&format!(
        "(deny file-map-executable (subpath \"{}\"))\n",
        scheme_string(&spec.work_dir)
    ));

    // Hardware identifiers (IOPlatformSerialNumber, board ids, ...) stay
    // unreadable; nothing a server runtime needs depends on them.
    profile.push_str("(deny iokit-get-properties)\n");

    profile
}

/// The literal paths whose metadata (stat) the child may read: every allowed
/// tree, every runtime path, and the path components leading to each of them.
///
/// `subpath` matching requires metadata on each ancestor, but a global allow
/// would expose the owner's home. Emitting the components as literals grants
/// exactly the traversal dyld and the runtime need.
fn metadata_literals(spec: &SandboxSpec) -> BTreeSet<String> {
    let mut literals = BTreeSet::new();
    literals.insert("/".to_string());
    insert_components(&mut literals, &spec.install_dir);
    insert_components(&mut literals, &spec.work_dir);
    for path in &spec.runtime_read_paths {
        insert_components(&mut literals, path);
    }
    for dir in SYSTEM_READ_DIRS {
        insert_components(&mut literals, Path::new(dir));
    }
    for file in SYSTEM_READ_FILES {
        insert_components(&mut literals, Path::new(file));
    }
    literals
}

/// Insert `path` and every ancestor of it into `literals`.
fn insert_components(literals: &mut BTreeSet<String>, path: &Path) {
    let mut current = Some(path);
    while let Some(component) = current {
        let text = scheme_string(component);
        if !text.is_empty() {
            literals.insert(text);
        }
        current = component.parent();
    }
}

/// Quote a path as a Scheme string in a Seatbelt profile.
///
/// Backslashes and quotes are escaped; control characters are dropped. A
/// control character cannot be represented safely and must never shape the
/// profile; dropping it makes the rule match no real path, which fails closed.
fn scheme_string(path: &Path) -> String {
    let mut out = String::new();
    for ch in path.to_string_lossy().chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ch if ch.is_control() => {}
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SandboxSpec {
        SandboxSpec {
            install_dir: PathBuf::from("/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2"),
            work_dir: PathBuf::from("/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work"),
            runtime_read_paths: vec![PathBuf::from("/usr/local/bin/node")],
            proxy_port: None,
        }
    }

    #[test]
    fn profile_is_deny_by_default_and_writes_only_the_work_dir() {
        let profile = seatbelt_profile(&spec());
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(
            profile.contains(
                "(allow file-write* (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
            ),
            "{profile}"
        );
        assert_eq!(profile.matches("(allow file-write*").count(), 1);
        // The install dir is readable but never writable.
        assert!(
            profile.contains("(subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2\")"),
            "{profile}"
        );
        let write_rule = profile
            .lines()
            .find(|line| line.starts_with("(allow file-write*"))
            .expect("write rule");
        assert!(!write_rule.contains("datagouv-mcp@1.4.2\")"));
    }

    #[test]
    fn metadata_is_scoped_and_not_global() {
        let profile = seatbelt_profile(&spec());
        // No bare global metadata allow.
        assert!(
            !profile.contains("(allow file-read-metadata)\n"),
            "{profile}"
        );
        assert!(
            profile.contains("(allow file-read-metadata (literal \"/\")"),
            "{profile}"
        );
        // The components leading to the install dir are present...
        assert!(
            profile.contains("(literal \"/Users/tester/.auxesis\")"),
            "{profile}"
        );
        assert!(
            profile.contains("(literal \"/Users/tester/.auxesis/extensions\")"),
            "{profile}"
        );
        // ...but the home itself is not a subpath metadata allow.
        assert!(
            !profile.contains("(allow file-read-metadata (subpath \"/Users/tester\")"),
            "{profile}"
        );
    }

    #[test]
    fn no_proxy_port_means_no_network_rule_at_all() {
        let profile = seatbelt_profile(&spec());
        assert!(!profile.contains("network"), "{profile}");
    }

    #[test]
    fn proxy_port_allows_only_tcp_on_the_ipv4_loopback_port() {
        let mut spec = spec();
        spec.proxy_port = Some(49_152);
        let profile = seatbelt_profile(&spec);
        assert!(
            profile.contains("(allow network-outbound (remote tcp4 \"localhost:49152\"))"),
            "{profile}"
        );
        assert!(!profile.contains("network-inbound"), "{profile}");
        assert!(!profile.contains("(allow network*)"), "{profile}");
        assert_eq!(profile.matches("network").count(), 1);
    }

    #[test]
    fn runtime_paths_are_executable_by_exact_path_and_readable() {
        let profile = seatbelt_profile(&spec());
        // Exec is the exact binary, never the whole directory.
        assert!(
            profile.contains("(allow process-exec* (literal \"/usr/local/bin/node\")"),
            "{profile}"
        );
        assert!(
            !profile.contains("(allow process-exec* (subpath \"/usr/local/bin\")"),
            "{profile}"
        );
        assert!(
            profile.contains("(allow file-read* (literal \"/\") (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2\")"),
            "{profile}"
        );
        assert!(
            profile.contains("(subpath \"/System/Library\")"),
            "{profile}"
        );
        // The dyld shared cache under the Preboot Cryptexes volume.
        assert!(
            profile.contains("(subpath \"/System/Volumes/Preboot/Cryptexes\")"),
            "{profile}"
        );
        assert!(profile.contains("(literal \"/\")"), "{profile}");
    }

    #[test]
    fn work_dir_is_never_executable() {
        let profile = seatbelt_profile(&spec());
        let deny = profile
            .lines()
            .position(|line| line.starts_with("(deny process-exec*"))
            .expect("work exec deny");
        let allow = profile
            .lines()
            .position(|line| line.starts_with("(allow process-exec*"))
            .expect("exec allow");
        assert!(
            allow < deny,
            "the work deny must come after the exec allow: {profile}"
        );
        assert!(
            profile.contains(
                "(deny process-exec* (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
            ),
            "{profile}"
        );
    }

    #[test]
    fn process_info_is_denied_and_only_self_is_allowed_back() {
        let profile = seatbelt_profile(&spec());
        let deny = profile
            .lines()
            .position(|line| line.starts_with("(deny process-info*"))
            .expect("process-info deny");
        let allow = profile
            .lines()
            .position(|line| line.starts_with("(allow process-info* (target self)"))
            .expect("process-info self allow");
        assert!(
            deny < allow,
            "the self allow must come after the global deny: {profile}"
        );
    }

    #[test]
    fn work_dir_cannot_be_mapped_and_iokit_properties_are_denied() {
        let profile = seatbelt_profile(&spec());
        assert!(
            profile.contains(
                "(deny file-map-executable (subpath \"/Users/tester/.auxesis/extensions/datagouv-mcp@1.4.2/work\"))"
            ),
            "{profile}"
        );
        assert!(profile.contains("(deny iokit-get-properties)"), "{profile}");
    }

    #[test]
    fn quotes_and_backslashes_in_paths_are_escaped() {
        let spec = SandboxSpec {
            install_dir: PathBuf::from("/tmp/inst\"all\\dir"),
            work_dir: PathBuf::from("/tmp/wo\"rk\\dir"),
            runtime_read_paths: Vec::new(),
            proxy_port: None,
        };
        let profile = seatbelt_profile(&spec);
        assert!(
            profile.contains("(subpath \"/tmp/inst\\\"all\\\\dir\")"),
            "{profile}"
        );
        assert!(
            profile.contains("(allow file-write* (subpath \"/tmp/wo\\\"rk\\\\dir\"))"),
            "{profile}"
        );
        // The quote never terminates the Scheme string early.
        assert!(!profile.contains("\"/tmp/inst\"all"), "{profile}");
    }

    #[test]
    fn control_characters_are_dropped_from_paths() {
        let spec = SandboxSpec {
            install_dir: PathBuf::from("/tmp/inst\nalldir"),
            work_dir: PathBuf::from("/tmp/work\rdir"),
            runtime_read_paths: Vec::new(),
            proxy_port: None,
        };
        let profile = seatbelt_profile(&spec);
        assert!(
            profile.contains("(subpath \"/tmp/installdir\")"),
            "{profile}"
        );
        assert!(
            profile.contains("(allow file-write* (subpath \"/tmp/workdir\"))"),
            "{profile}"
        );
    }

    // ------------------------------------------------------------------
    // Real `sandbox-exec` checks. Ignored by default because they run the
    // platform sandbox; run them explicitly on macOS with
    // `cargo test -p kernel-mcp -- --ignored --nocapture`.
    // ------------------------------------------------------------------

    /// Run `program` under `profile`, returning its exit status and stderr.
    #[cfg(target_os = "macos")]
    fn run_under(profile: &str, program: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(profile)
            .arg(program)
            .args(args)
            .output()
            .expect("run sandbox-exec")
    }

    /// Canonicalise a path the kernel will match against.
    #[cfg(target_os = "macos")]
    fn canonical(path: &Path) -> PathBuf {
        path.canonicalize().expect("canonical path")
    }

    /// A spec rooted in fresh temp dirs, with the given runtime paths.
    #[cfg(target_os = "macos")]
    fn temp_spec_paths(
        runtime: Vec<PathBuf>,
        proxy_port: Option<u16>,
    ) -> (tempfile::TempDir, SandboxSpec) {
        let root = tempfile::tempdir().expect("install dir");
        let install = canonical(root.path());
        let work = install.join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        let spec = SandboxSpec {
            install_dir: install,
            work_dir: work,
            runtime_read_paths: runtime,
            proxy_port,
        };
        (root, spec)
    }

    /// A spec rooted in fresh temp dirs, with the given exact interpreters.
    #[cfg(target_os = "macos")]
    fn temp_spec(runtime: &[&str], proxy_port: Option<u16>) -> (tempfile::TempDir, SandboxSpec) {
        temp_spec_paths(runtime.iter().map(PathBuf::from).collect(), proxy_port)
    }

    /// A tiny C probe for the operations no stock CLI exposes: reading another
    /// process's argv (`sysctl KERN_PROCARGS2`) and path (`proc_pidpath`),
    /// `dlopen`, the IOKit platform serial, and a raw TCP/UDP connect. It
    /// never prints the serial value, only whether the read succeeded.
    #[cfg(target_os = "macos")]
    const PROBE_C: &str = r##"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <dlfcn.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

static int fill(struct sockaddr_in *a, const char *host, const char *port) {
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port = htons((unsigned short)atoi(port));
    return inet_pton(AF_INET, host, &a->sin_addr) == 1 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("USAGE\n"); return 2; }
    if (!strcmp(argv[1], "args") && argc == 3) {
        int mib[3] = {CTL_KERN, KERN_PROCARGS2, atoi(argv[2])};
        size_t size = 0;
        if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) { printf("ARGS_DENIED:%d\n", errno); return 0; }
        char *buf = malloc(size ? size : 1);
        if (sysctl(mib, 3, buf, &size, NULL, 0) != 0) { printf("ARGS_DENIED:%d\n", errno); free(buf); return 0; }
        printf("ARGS_OK\n"); free(buf); return 0;
    }
    if (!strcmp(argv[1], "path") && argc == 3) {
        char buf[4096];
        if (proc_pidpath(atoi(argv[2]), buf, sizeof(buf)) <= 0) { printf("PATH_DENIED:%d\n", errno); return 0; }
        printf("PATH_OK\n"); return 0;
    }
    if (!strcmp(argv[1], "dlopen") && argc == 3) {
        void *h = dlopen(argv[2], RTLD_NOW);
        if (!h) { printf("DLOPEN_FAIL\n"); return 0; }
        printf("DLOPEN_OK\n"); dlclose(h); return 0;
    }
    if (!strcmp(argv[1], "serial")) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
        if (!svc) { printf("SERIAL_DENIED:nomatch\n"); return 0; }
        CFTypeRef prop = IORegistryEntryCreateCFProperty(svc, CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
        if (!prop) { printf("SERIAL_DENIED:noprop\n"); IOObjectRelease(svc); return 0; }
        CFRelease(prop); IOObjectRelease(svc); printf("SERIAL_OK\n"); return 0;
    }
    if (!strcmp(argv[1], "tcp") && argc == 4) {
        struct sockaddr_in a;
        if (fill(&a, argv[2], argv[3]) != 0) { printf("TCP_BADADDR\n"); return 0; }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { printf("TCP_DENIED:%d\n", errno); return 0; }
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { printf("TCP_DENIED:%d\n", errno); close(fd); return 0; }
        printf("TCP_OK\n"); close(fd); return 0;
    }
    if (!strcmp(argv[1], "udp") && argc == 4) {
        struct sockaddr_in a;
        if (fill(&a, argv[2], argv[3]) != 0) { printf("UDP_BADADDR\n"); return 0; }
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { printf("UDP_DENIED:%d\n", errno); return 0; }
        if (sendto(fd, "x", 1, 0, (struct sockaddr *)&a, sizeof(a)) < 0) { printf("UDP_DENIED:%d\n", errno); close(fd); return 0; }
        printf("UDP_OK\n"); close(fd); return 0;
    }
    printf("UNKNOWN\n"); return 2;
}
"##;

    /// Compile [`PROBE_C`] into the (executable) install dir and return its path.
    #[cfg(target_os = "macos")]
    fn compile_probe(install_dir: &Path) -> PathBuf {
        let source = install_dir.join("probe.c");
        std::fs::write(&source, PROBE_C).expect("write probe.c");
        let binary = install_dir.join("probe");
        let status = std::process::Command::new("/usr/bin/cc")
            .arg("-O0")
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .args(["-framework", "IOKit", "-framework", "CoreFoundation"])
            .status()
            .expect("run cc");
        assert!(status.success(), "cc could not build the probe helper");
        binary
    }

    /// A trivial dylib with no dependencies, for the `dlopen` test.
    #[cfg(target_os = "macos")]
    fn compile_dylib(dir: &Path, name: &str) -> PathBuf {
        let source = dir.join("dylib.c");
        std::fs::write(&source, "int probe_symbol(void) { return 42; }\n").expect("write dylib.c");
        let dylib = dir.join(name);
        let status = std::process::Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-o"])
            .arg(&dylib)
            .arg(&source)
            .status()
            .expect("run cc");
        assert!(status.success(), "cc could not build the test dylib");
        dylib
    }

    /// The canonical node binary and the read paths it needs, if node is
    /// installed. `None` skips the node positive control on a host without it.
    #[cfg(target_os = "macos")]
    fn node_runtime() -> Option<(PathBuf, Vec<PathBuf>)> {
        let node = ["/opt/homebrew/bin/node", "/usr/local/bin/node"]
            .iter()
            .map(Path::new)
            .find(|path| path.exists())
            .and_then(|path| path.canonicalize().ok())?;
        let lib = node.parent()?.parent()?.join("lib");
        let mut runtime = vec![PathBuf::from("/usr/bin/true"), node.clone(), lib];
        for path in [
            "/opt/homebrew/opt",
            "/opt/homebrew/Cellar",
            "/opt/homebrew/lib",
            "/opt/homebrew/etc/openssl@3/openssl.cnf",
            "/opt/homebrew/etc/ca-certificates",
        ] {
            let path = PathBuf::from(path);
            if path.exists() {
                runtime.push(path);
            }
        }
        Some((node, runtime))
    }

    /// Positive control: the node runtime still starts under the tightened
    /// profile. Skipped, not failed, when node is not installed.
    #[cfg(target_os = "macos")]
    fn assert_node_starts() {
        let Some((node, runtime)) = node_runtime() else {
            eprintln!("node not installed; skipping the node positive control");
            return;
        };
        let (_root, spec) = temp_spec_paths(runtime, None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let out = run_under(
            &profile,
            node.to_str().expect("utf-8"),
            &["-e", "console.log('node ok')"],
        );
        assert!(
            out.status.success() && out.stdout == b"node ok\n",
            "node must still start: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Positive control for every denial test: `/usr/bin/true` exits 0 under
    /// the profile, so a non-zero exit below means the sandbox denied it, not
    /// that the profile cannot run anything at all.
    #[cfg(target_os = "macos")]
    fn assert_true_runs(profile: &str) {
        let out = run_under(profile, "/usr/bin/true", &[]);
        assert!(
            out.status.success(),
            "positive control /usr/bin/true failed: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_runs_a_plain_child_under_the_profile() {
        let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/echo"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let out = run_under(&profile, "/bin/echo", &["hi"]);
        assert!(
            out.status.success() && out.stdout == b"hi\n",
            "/bin/echo must run: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_network() {
        // No proxy port: no network rule at all, so even loopback is denied.
        let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/nc"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let out = run_under(
            &profile,
            "/usr/bin/nc",
            &["-z", "-w", "2", "1.1.1.1", "443"],
        );
        assert!(
            !out.status.success(),
            "the sandbox must deny the outbound connection, got {:?}",
            out.status
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_allows_only_the_proxy_port_on_ipv4_loopback() {
        use std::net::TcpListener;

        // A listener on the allowed port, one on a *different* loopback port,
        // and one on IPv6 loopback. Keeping them open makes a refused connect
        // distinguishable from a sandbox denial only by the exit status; we
        // assert the denied cases fail even though something is listening.
        let allowed = TcpListener::bind(("127.0.0.1", 0)).expect("allowed listener");
        let allowed_port = allowed.local_addr().expect("addr").port();
        let other = TcpListener::bind(("127.0.0.1", 0)).expect("other listener");
        let other_port = other.local_addr().expect("addr").port();
        let v6 = TcpListener::bind(("::1", 0)).expect("v6 listener");
        let v6_port = v6.local_addr().expect("addr").port();
        for listener in [&allowed, &other, &v6] {
            listener.set_nonblocking(true).expect("nonblocking");
        }

        let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/nc"], Some(allowed_port));
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        // Positive control: the allowed port connects.
        let out = run_under(
            &profile,
            "/usr/bin/nc",
            &["-z", "-w", "2", "127.0.0.1", &allowed_port.to_string()],
        );
        assert!(
            out.status.success(),
            "the proxy port must connect: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        // A different loopback port, IPv6 loopback and a public address are all
        // denied even though the first two have listeners.
        for (host, port) in [
            ("127.0.0.1", other_port.to_string()),
            ("::1", v6_port.to_string()),
            ("1.1.1.1", "443".to_string()),
        ] {
            let out = run_under(&profile, "/usr/bin/nc", &["-z", "-w", "2", host, &port]);
            assert!(
                !out.status.success(),
                "{host}:{port} must be denied, got {:?}",
                out.status
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_reads_and_stats_outside_the_allowed_paths() {
        let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/cat", "/usr/bin/stat"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        // A decoy in a temp HOME: not an ancestor of any allowed path, so its
        // metadata (and therefore stat) and its data are denied.
        let home = tempfile::tempdir().expect("decoy home");
        let decoy = home.path().join("decoy.txt");
        std::fs::write(&decoy, b"secret").expect("write decoy");

        let out = run_under(&profile, "/bin/cat", &[decoy.to_str().expect("utf-8")]);
        assert!(
            !out.status.success(),
            "reading a decoy outside the allowed paths must fail, got {:?}",
            out.status
        );
        let out = run_under(&profile, "/usr/bin/stat", &[decoy.to_str().expect("utf-8")]);
        assert!(
            !out.status.success(),
            "stat of a decoy in the temp HOME must fail, got {:?}",
            out.status
        );

        // Positive control: a file inside work/ is readable.
        let inside = spec.work_dir.join("ok.txt");
        std::fs::write(&inside, b"data").expect("write inside");
        let out = run_under(&profile, "/bin/cat", &[inside.to_str().expect("utf-8")]);
        assert!(
            out.status.success() && out.stdout == b"data",
            "reading work/ must succeed: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_writes_outside_the_work_dir() {
        let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/touch"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        let home = tempfile::tempdir().expect("decoy home");
        let outside = home.path().join("nope.txt");
        let out = run_under(
            &profile,
            "/usr/bin/touch",
            &[outside.to_str().expect("utf-8")],
        );
        assert!(
            !out.status.success(),
            "writing outside work/ must fail, got {:?}",
            out.status
        );

        // Positive control: writing inside work/ succeeds.
        let inside = spec.work_dir.join("made.txt");
        let out = run_under(
            &profile,
            "/usr/bin/touch",
            &[inside.to_str().expect("utf-8")],
        );
        assert!(
            out.status.success() && inside.exists(),
            "writing work/ must succeed: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_exec_of_a_binary_copied_into_work() {
        let (_root, spec) = temp_spec(&["/usr/bin/true"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        let copy = spec.work_dir.join("truecopy");
        std::fs::copy("/usr/bin/true", &copy).expect("copy true");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let out = run_under(&profile, copy.to_str().expect("utf-8"), &[]);
        assert!(
            !out.status.success(),
            "a binary copied into work/ must not execute, got {:?}",
            out.status
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_exec_of_curl() {
        // curl is not among the runtime interpreters.
        let (_root, spec) = temp_spec(&["/usr/bin/true"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let out = run_under(&profile, "/usr/bin/curl", &["--version"]);
        assert!(
            !out.status.success(),
            "/usr/bin/curl must not execute, got {:?}",
            out.status
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_execs_a_shebang_script_only_through_its_exact_interpreter() {
        let (_root, spec) = temp_spec(&["/usr/bin/true", "/bin/cat"], None);
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        // /bin/cat is an allowed interpreter, so its script runs.
        let ok = spec.install_dir.join("runme");
        std::fs::write(&ok, b"#!/bin/cat\nhello\n").expect("write ok script");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o755)).expect("chmod ok");
        let out = run_under(&profile, ok.to_str().expect("utf-8"), &[]);
        assert!(
            out.status.success() && out.stdout == b"#!/bin/cat\nhello\n",
            "a script with an allowed interpreter must run: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        // The same script with a disallowed interpreter does not run, even
        // though the script file itself sits in the executable install dir.
        let blocked = spec.install_dir.join("blocked");
        std::fs::write(&blocked, b"#!/usr/bin/curl\nhello\n").expect("write blocked script");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let out = run_under(&profile, blocked.to_str().expect("utf-8"), &[]);
        assert!(
            !out.status.success(),
            "a script with a disallowed interpreter must not run, got {:?}",
            out.status
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_other_process_info() {
        let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
        let probe = compile_probe(&spec.install_dir);
        spec.runtime_read_paths.push(probe.clone());
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        // A same-uid decoy with a marker in its environment. Only denial is
        // asserted; the marker is never read or printed.
        let mut decoy = std::process::Command::new("/bin/sleep")
            .arg("120")
            .env("AUX_DECOY_TOKEN", "decoy-round2-not-a-secret")
            .spawn()
            .expect("spawn decoy");
        let pid = decoy.id().to_string();
        let probe = probe.to_str().expect("utf-8");

        let args = run_under(&profile, probe, &["args", &pid]);
        assert!(
            args.status.success()
                && String::from_utf8_lossy(&args.stdout).starts_with("ARGS_DENIED"),
            "KERN_PROCARGS2 on another process must be denied: {:?} {}",
            args.status,
            String::from_utf8_lossy(&args.stdout)
        );
        let path = run_under(&profile, probe, &["path", &pid]);
        assert!(
            path.status.success()
                && String::from_utf8_lossy(&path.stdout).starts_with("PATH_DENIED"),
            "proc_pidpath on another process must be denied: {:?} {}",
            path.status,
            String::from_utf8_lossy(&path.stdout)
        );

        let _ = decoy.kill();
        let _ = decoy.wait();
        assert_node_starts();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_dlopen_of_a_dylib_in_work() {
        let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
        let probe = compile_probe(&spec.install_dir);
        spec.runtime_read_paths.push(probe.clone());
        // The install-dir copy is the positive control; the work/ copy is the
        // one the file-map-executable deny must block.
        let install_dylib = compile_dylib(&spec.install_dir, "libprobe.dylib");
        let work_dylib = spec.work_dir.join("libprobe.dylib");
        std::fs::copy(&install_dylib, &work_dylib).expect("copy dylib into work");
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let probe = probe.to_str().expect("utf-8");

        let ok = run_under(
            &profile,
            probe,
            &["dlopen", install_dylib.to_str().expect("utf-8")],
        );
        assert!(
            ok.status.success() && ok.stdout == b"DLOPEN_OK\n",
            "dlopen from the install dir must work: {:?} {}",
            ok.status,
            String::from_utf8_lossy(&ok.stdout)
        );
        let denied = run_under(
            &profile,
            probe,
            &["dlopen", work_dylib.to_str().expect("utf-8")],
        );
        assert!(
            denied.status.success() && denied.stdout == b"DLOPEN_FAIL\n",
            "dlopen from work/ must be denied: {:?} {}",
            denied.status,
            String::from_utf8_lossy(&denied.stdout)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_denies_iokit_platform_serial() {
        let (_root, mut spec) = temp_spec(&["/usr/bin/true"], None);
        let probe = compile_probe(&spec.install_dir);
        spec.runtime_read_paths.push(probe.clone());
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);

        let out = run_under(&profile, probe.to_str().expect("utf-8"), &["serial"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.starts_with("SERIAL_DENIED"),
            "the platform serial must be unreadable: {:?} {stdout}",
            out.status
        );
        // The probe prints only the denial shape, never a serial value.
        assert!(!stdout.contains("SERIAL_OK"), "{stdout}");
        assert_node_starts();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "runs the real macOS sandbox; run with --ignored"]
    fn sandbox_allows_only_tcp_on_the_proxy_port() {
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");

        let (_root, mut spec) = temp_spec(&["/usr/bin/true"], Some(port));
        let probe = compile_probe(&spec.install_dir);
        spec.runtime_read_paths.push(probe.clone());
        let profile = seatbelt_profile(&spec);
        assert_true_runs(&profile);
        let probe = probe.to_str().expect("utf-8");

        // TCP is the one allowed transport.
        let tcp = run_under(&profile, probe, &["tcp", "127.0.0.1", &port.to_string()]);
        assert!(
            tcp.status.success() && tcp.stdout == b"TCP_OK\n",
            "TCP to the proxy port must connect: {:?} {}",
            tcp.status,
            String::from_utf8_lossy(&tcp.stdout)
        );
        // UDP on the same port stays denied.
        let udp = run_under(&profile, probe, &["udp", "127.0.0.1", &port.to_string()]);
        assert!(
            udp.status.success() && String::from_utf8_lossy(&udp.stdout).starts_with("UDP_DENIED"),
            "UDP must be denied: {:?} {}",
            udp.status,
            String::from_utf8_lossy(&udp.stdout)
        );
    }
}
