//! `owner_profile` — what the Mac already knows about the owner, so an agent
//! asks only for what is missing. Read-only, local sources only: the owner's
//! CRM card, the owner's own contacts entry, and saved `owner.*` memory facts.
use async_trait::async_trait;
use aux_store::{PartyKind, Store, StoreError};
use kernel_broker::ToolClass;
use kernel_broker::{sanitize_text, NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput, Trust};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

const FIELDS: [&str; 7] = [
    "name",
    "email",
    "phone",
    "address",
    "company",
    "language",
    "time_zone",
];

/// Returns the owner's known details and the list of what is missing.
pub struct OwnerProfileTool {
    store: Arc<Mutex<Store>>,
    /// The interface language from `[ui].language`, when the host passes it.
    language: Option<String>,
}

impl OwnerProfileTool {
    pub fn new(store: Arc<Mutex<Store>>, language: Option<String>) -> Self {
        Self { store, language }
    }
}

/// E.164: `+` then 8 to 15 digits. A local number is never completed with a
/// guessed country, so anything else is dropped.
fn e164(raw: &str) -> Option<String> {
    let digits = raw.strip_prefix('+')?;
    ((8..=15).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| raw.to_string())
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    let value = sanitize_text(value);
    if !value.is_empty() && !list.contains(&value) {
        list.push(value);
    }
}

/// Set `slot` once, from the first non-empty value.
fn first_text(slot: &mut Option<String>, value: &str) {
    let value = sanitize_text(value);
    if slot.is_none() && !value.is_empty() {
        *slot = Some(value);
    }
}

#[derive(Default)]
struct Profile {
    name: Option<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    addresses: Vec<String>,
    company: Option<String>,
    time_zone: Option<String>,
}

impl Profile {
    fn add_contact(&mut self, name: &str, emails: &[String], phones: &[String]) {
        first_text(&mut self.name, name);
        emails.iter().for_each(|e| push_unique(&mut self.emails, e));
        phones
            .iter()
            .filter_map(|n| e164(n))
            .for_each(|n| push_unique(&mut self.phones, &n));
    }

    fn gather(store: &Store, agent: &str) -> Result<Self, StoreError> {
        let mut p = Self::default();
        for party in store.parties()? {
            if party.origin == "owner" && party.kind == PartyKind::Person {
                p.add_contact(&party.display_name, &party.emails, &party.phones);
                party
                    .addresses
                    .iter()
                    .for_each(|a| push_unique(&mut p.addresses, a));
            }
        }
        for c in store.contacts()?.iter().filter(|c| c.source == "owner") {
            let name = c.display_name.clone();
            let name =
                name.unwrap_or_else(|| format!("{} {}", c.given.join(" "), c.family.join(" ")));
            p.add_contact(name.trim(), &c.emails, &c.phones);
        }
        for (key, value) in store.owner_facts(agent)? {
            match key.as_str() {
                "owner.name" => first_text(&mut p.name, &value),
                "owner.email" => push_unique(&mut p.emails, &value),
                "owner.phone" => e164(&value)
                    .iter()
                    .for_each(|n| push_unique(&mut p.phones, n)),
                "owner.address" => push_unique(&mut p.addresses, &value),
                "owner.company" => first_text(&mut p.company, &value),
                "owner.time_zone" => first_text(&mut p.time_zone, &value),
                _ => {}
            }
        }
        Ok(p)
    }
}

impl NativeTool for OwnerProfileTool {
    fn native_name(&self) -> &'static str {
        "owner_profile"
    }

    fn native_description(&self) -> &'static str {
        "Return what is already known about the owner (name, emails, phones, address, company, language, time zone) and what is missing. Call it before asking the owner for personal details."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
            || json!({"type":"object","properties":{},"additionalProperties":false}),
        );
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for OwnerProfileTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B23
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        if args.as_object().is_none_or(|o| !o.is_empty()) {
            return Err(ToolError::invalid_args(self.name(), "takes no arguments"));
        }
        let p = {
            let store = self.store.lock().unwrap_or_else(|p| p.into_inner());
            Profile::gather(&store, &ctx.agent).map_err(|e| ToolError::fetch(e.to_string()))?
        };
        let mut known = Map::new();
        let mut put = |key: &str, value: Option<Value>| {
            if let Some(value) = value {
                known.insert(key.to_string(), value);
            }
        };
        let list = |items: Vec<String>| (!items.is_empty()).then(|| json!(items));
        put("name", p.name.map(Value::from));
        put("emails", list(p.emails));
        put("phones", list(p.phones));
        put("address", list(p.addresses));
        put("company", p.company.map(Value::from));
        put("language", self.language.clone().map(Value::from));
        put("time_zone", p.time_zone.map(Value::from));
        let missing: Vec<&str> = FIELDS
            .into_iter()
            .filter(|field| {
                let key = match *field {
                    "email" => "emails",
                    "phone" => "phones",
                    other => other,
                };
                !known.contains_key(key)
            })
            .collect();
        Ok(ToolOutput::ok(
            json!({"known": known, "missing": missing}).to_string(),
        ))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: true,
            output_trust: Trust::Trusted,
            ..ToolClass::default()
        }
    }
}
