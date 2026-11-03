//! S2 naming tests: exact wire names, fail-closed collisions, and lookup.

use kernel_mcp::naming::{
    display_name, logical_name, sanitize_wire_component, wire_name, WireNames, MAX_WIRE_NAME_BYTES,
};

fn provider_legal(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_WIRE_NAME_BYTES
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[test]
fn golden_wire_name() {
    let wire = wire_name("fakeserv", "ZOHO_CRM_CONVERT_LEAD_TO_CONTACT");
    assert_eq!(wire, "mcp__fakeserv__ZOHO_CRM_CONVERT_LEAD_TO_CONTACT");
    assert!(provider_legal(&wire));
}

#[test]
fn overlong_wire_name_is_never_truncated_or_registered() {
    let remote = "A".repeat(200);
    let wire = wire_name("fakeserv", &remote);
    assert_eq!(wire, format!("mcp__fakeserv__{remote}"));
    assert!(wire.len() > MAX_WIRE_NAME_BYTES);
    let mut names = WireNames::new();
    assert_eq!(names.register("fakeserv", &remote), None);
    assert!(names.wire_for("fakeserv", &remote).is_none());
}

#[test]
fn illegal_characters_become_underscores_and_hyphens_survive() {
    assert_eq!(sanitize_wire_component("a.b-c"), "a_b-c");
    assert_eq!(sanitize_wire_component("a.b\u{1F600}c"), "a_b_c");
    assert_eq!(sanitize_wire_component("日本語"), "___");
}

#[test]
fn display_and_logical_names_are_dotted() {
    assert_eq!(
        display_name("fakeserv", "ZOHO_CRM_X"),
        "mcp.fakeserv.ZOHO_CRM_X"
    );
    assert_eq!(
        logical_name("fakeserv", "zoho", "ZOHO_CRM_X"),
        "fakeserv.zoho.ZOHO_CRM_X"
    );
}

#[test]
fn two_servers_with_the_same_remote_name_are_distinct_and_resolvable() {
    let mut names = WireNames::default();
    let alpha = names.register("alpha", "SEARCH_RECORDS").unwrap();
    let beta = names.register("beta", "SEARCH_RECORDS").unwrap();
    assert_ne!(alpha, beta);
    assert_eq!(names.resolve(&alpha), Some(("alpha", "SEARCH_RECORDS")));
    assert_eq!(names.resolve(&beta), Some(("beta", "SEARCH_RECORDS")));
    assert_eq!(
        names.wire_for("alpha", "SEARCH_RECORDS"),
        Some(alpha.as_str())
    );
    // Re-registering the same identity is idempotent.
    assert_eq!(names.register("alpha", "SEARCH_RECORDS"), Some(alpha));
}

#[test]
fn invalid_components_and_exact_collisions_are_rejected() {
    let mut names = WireNames::default();
    assert_eq!(names.register("a.b", "X"), None);
    assert!(names.wire_for("a.b", "X").is_none());

    // The separator makes these two distinct identities produce the same
    // exact wire name. Neither identity is allowed to win.
    let first = ("a__b".to_owned(), "c".to_owned());
    let second = ("a".to_owned(), "b__c".to_owned());
    assert_eq!(
        wire_name(&first.0, &first.1),
        wire_name(&second.0, &second.1)
    );
    names.register_all(&[first.clone(), second.clone()]);
    assert!(names.wire_for(&first.0, &first.1).is_none());
    assert!(names.wire_for(&second.0, &second.1).is_none());
}

#[test]
fn exact_collision_rejection_is_independent_of_registration_order() {
    let mut forward = WireNames::default();
    let _ = forward.register("a__b", "c");
    let _ = forward.register("a", "b__c");

    let mut reverse = WireNames::default();
    let _ = reverse.register("a", "b__c");
    let _ = reverse.register("a__b", "c");

    for (server, remote) in [("a__b", "c"), ("a", "b__c")] {
        assert_eq!(
            forward.wire_for(server, remote),
            reverse.wire_for(server, remote),
            "registration order changed the wire name for {server}"
        );
        assert_eq!(forward.wire_for(server, remote), None);
        assert_eq!(reverse.wire_for(server, remote), None);
    }
}
