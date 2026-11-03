//! The `[privacy] mask_first_names` key, end to end: kernel-core parses the section,
//! and the value handed to `RegistryBuilder::mask_first_names` decides whether a
//! lone given name in a greeting is left in clear. Fake data only.

use kernel_core::config::Config;
use kernel_privacy::{EntityKind, Registry};

/// The person values the default registry finds in `text`, with the bare-first-name
/// switch taken from the parsed `config_toml`.
fn persons_for(config_toml: &str, text: &str) -> Vec<String> {
    let config: Config = toml::from_str(config_toml).expect("config parses");
    Registry::builder()
        .with_all()
        .mask_first_names(config.privacy.mask_first_names)
        .build()
        .analyze(text)
        .into_iter()
        .filter(|span| span.kind == EntityKind::Person)
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}

#[test]
fn a_missing_key_leaves_a_vocative_given_name_in_clear() {
    for config in ["version = 1\n", "[privacy]\nmode = \"private\"\n"] {
        let persons = persons_for(config, "Salut Jules\n");
        assert!(
            !persons.iter().any(|value| value == "Jules"),
            "{config:?} masked a vocative given name: {persons:?}"
        );
    }
}

#[test]
fn mask_first_names_true_is_parsed_and_applied() {
    let persons = persons_for("[privacy]\nmask_first_names = true\n", "Salut Jules\n");
    assert!(
        persons.iter().any(|value| value == "Jules"),
        "the parsed switch did not reach the registry: {persons:?}"
    );
}

#[test]
fn mask_first_names_false_is_parsed_and_applied() {
    let persons = persons_for("[privacy]\nmask_first_names = false\n", "Salut Jules\n");
    assert!(!persons.iter().any(|value| value == "Jules"), "{persons:?}");
}
