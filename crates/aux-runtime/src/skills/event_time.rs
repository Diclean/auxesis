//! The time of a calendar event, resolved before its card (M4-2).
//!
//! The model writes the owner's wall time and maybe an IANA zone, never an
//! offset (it is told only today's). The card shows the zone, real offsets,
//! the UTC instants the `.ics` carries and the invitee's local start. Unknown
//! zones, skipped or repeated times and wrong offsets are refused; no zone is
//! assumed. Reasons never echo a value: they go back to the model.

use chrono::{DateTime, LocalResult, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::{Map, Value};

/// The logical tool whose times are resolved.
pub const EVENT_CREATE: &str = "calendar.create_event";

/// The logical update, whose new times are resolved the same way.
pub const EVENT_UPDATE: &str = "calendar.update_event";

/// The card field that says where the attendee's zone came from. Auxesis sets
/// it, never the model: the client card's stored zone, or the model's own
/// `attendee_time_zone` when the client has none.
pub const ATTENDEE_ZONE_SOURCE: &str = "attendee_time_zone_source";

/// The owner's system zone: `TZ` when it names one, else the `/etc/localtime`
/// link (`…/zoneinfo/Europe/Paris` on macOS). `None` when neither does.
pub fn owner_time_zone() -> Option<String> {
    let from_env = std::env::var("TZ").ok().map(|n| n.replace(':', ""));
    let from_link = || {
        let target = std::fs::read_link("/etc/localtime").ok()?;
        let (_, name) = target.to_str()?.split_once("zoneinfo/")?;
        Some(name.to_string())
    };
    let known = |name: &String| name.parse::<Tz>().is_ok();
    from_env.filter(known).or_else(|| from_link().filter(known))
}

/// Resolve a create's times in its `time_zone`, else `owner_zone` (stated on
/// the card). Idempotent, so an owner edit goes through the same rules.
pub fn resolve_event_times(arguments: &Value, owner_zone: Option<&str>) -> Result<Value, String> {
    resolve_event_times_for_client(arguments, owner_zone, None)
}

/// [`resolve_event_times`] with the known client's stored IANA zone. When
/// `client_zone` names a zone it replaces the model's `attendee_time_zone`,
/// even a different one; the card's `attendee_time_zone_source` line says the
/// client card supplied it and names what the model said. A client with no
/// stored zone (or one that is not an IANA name) keeps today's behaviour: the
/// model's argument decides.
pub fn resolve_event_times_for_client(
    arguments: &Value,
    owner_zone: Option<&str>,
    client_zone: Option<&str>,
) -> Result<Value, String> {
    let mut map: Map<String, Value> = arguments
        .as_object()
        .cloned()
        .ok_or("the event arguments are not an object")?;
    let zone_name = match zone_field(&map, "time_zone")? {
        Some(name) => name,
        None => owner_zone
            .ok_or("the owner's time zone is unknown: name the zone, such as Europe/Paris")?
            .to_string(),
    };
    let zone = parse_zone(&zone_name, "time_zone")?;
    let start = instant(map.get("start"), "start", zone)?;
    map.insert("time_zone".into(), Value::String(zone_name));
    map.insert("start".into(), Value::String(start.to_rfc3339()));
    map.insert("start_utc".into(), Value::String(compact(&start)));
    if map.contains_key("end") {
        let end = instant(map.get("end"), "end", zone)?;
        if end <= start {
            return Err("the event ends before it starts".to_string());
        }
        map.insert("end".into(), Value::String(end.to_rfc3339()));
        map.insert("end_utc".into(), Value::String(compact(&end)));
    } else {
        map.remove("end_utc");
    }
    map.remove("attendee_start");
    let model_zone = zone_field(&map, "attendee_time_zone")?;
    let stored = client_zone.and_then(valid_zone);
    if let Some(name) = &stored {
        // A second resolution keeps the note it already wrote: the model's
        // value is gone by then, replaced by the stored one.
        let already_client = model_zone
            .as_deref()
            .is_some_and(|model| model.eq_ignore_ascii_case(name));
        let source = match map
            .get(ATTENDEE_ZONE_SOURCE)
            .and_then(Value::as_str)
            .filter(|_| already_client)
        {
            Some(previous) => previous.to_string(),
            None => match model_zone.as_deref() {
                Some(model) if !model.eq_ignore_ascii_case(name) => {
                    format!("client card (the model said {model})")
                }
                _ => "client card".to_string(),
            },
        };
        map.insert("attendee_time_zone".into(), Value::String(name.clone()));
        map.insert(ATTENDEE_ZONE_SOURCE.into(), Value::String(source));
    }
    if let Some(name) = zone_field(&map, "attendee_time_zone")? {
        let theirs = start.with_timezone(&parse_zone(&name, "attendee_time_zone")?);
        let theirs = Value::String(theirs.fixed_offset().to_rfc3339());
        map.insert("attendee_start".into(), theirs);
    }
    Ok(Value::Object(map))
}

/// The IANA zone a stored value names, trimmed; `None` when it is not one.
fn valid_zone(name: &str) -> Option<String> {
    let name = name.trim();
    name.parse::<Tz>().ok().map(|_| name.to_string())
}

/// Resolve an update's new times like a create's; a new end needs its start.
pub fn resolve_update_times(arguments: &Value, owner_zone: Option<&str>) -> Result<Value, String> {
    match (arguments.get("start"), arguments.get("end")) {
        (Some(_), _) => resolve_event_times(arguments, owner_zone),
        (None, Some(_)) => Err("an update that changes the end gives the new start too".into()),
        (None, None) => Ok(arguments.clone()),
    }
}

fn zone_field(map: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    match map.get(field) {
        None => Ok(None),
        Some(Value::String(name)) => Ok(Some(name.clone())),
        Some(_) => Err(format!("`{field}` must be a zone name")),
    }
}

fn parse_zone(name: &str, field: &str) -> Result<Tz, String> {
    name.parse::<Tz>().map_err(|_| {
        format!("unknown time zone in `{field}`: name an IANA zone, such as Europe/Paris")
    })
}

/// The instant of `field`: a wall time without offset is read in `zone`; one
/// with an offset must carry `zone`'s own offset at that instant.
fn instant(value: Option<&Value>, field: &str, zone: Tz) -> Result<DateTime<Tz>, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the event has no `{field}`"))?;
    if let Ok(given) = DateTime::parse_from_rfc3339(text) {
        let at = given.with_timezone(&zone);
        if at.offset().fix() != *given.offset() {
            return Err(format!(
                "the event `{field}` carries an offset that is not {zone}'s on that day ({}): \
                 write the local time without an offset",
                at.format("%:z")
            ));
        }
        return Ok(at);
    }
    let wall = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M"))
        .map_err(|_| {
            format!("the event `{field}` is not a local date and time such as 2026-10-26T10:00:00")
        })?;
    match zone.from_local_datetime(&wall) {
        LocalResult::Single(at) => Ok(at),
        LocalResult::Ambiguous(first, second) => Err(format!(
            "the event `{field}` happens twice in {zone} (the clocks go back): \
             add the offset, {} or {}",
            first.format("%:z"),
            second.format("%:z")
        )),
        LocalResult::None => Err(format!(
            "the event `{field}` does not exist in {zone} (the clocks skip it)"
        )),
    }
}

/// The RFC 5545 UTC form the `.ics` carries.
fn compact(at: &DateTime<Tz>) -> String {
    at.with_timezone(&Utc).format("%Y%m%dT%H%M%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_update_resolves_its_new_times_and_refuses_an_end_alone() {
        let paris = Some("Europe/Paris");
        let at = |start: &str, end: &str| json!({ "event_id": "e", "start": start, "end": end });
        let resolved = resolve_update_times(&at("2026-10-31T15:00", "2026-10-31T16:00"), paris);
        let resolved = resolved.unwrap();
        assert_eq!(resolved["start_utc"], "20261031T140000Z");
        assert_eq!(resolve_update_times(&resolved, paris).unwrap(), resolved);
        assert!(resolve_update_times(&at("2026-10-31T15:00", "2026-10-31T14:00"), paris).is_err());
        assert!(resolve_update_times(&json!({ "end": "2026-10-31T16:00" }), paris).is_err());
    }

    #[test]
    fn a_missing_zone_is_the_owners_and_a_resolved_event_resolves_to_itself() {
        let args = json!({"title": "M", "start": "2026-10-26T10:00:00", "end": "2026-10-26T10:30"});
        let resolved = resolve_event_times(&args, Some("America/New_York")).unwrap();
        assert_eq!(resolved["time_zone"], "America/New_York");
        assert_eq!(resolved["start_utc"], "20261026T140000Z");
        assert_eq!(resolve_event_times(&resolved, None).unwrap(), resolved);
        let err = resolve_event_times(&args, None).unwrap_err();
        assert!(err.contains("time zone is unknown"), "{err}");
    }

    #[test]
    fn a_wall_time_is_read_in_the_events_zone_not_the_owners() {
        // Paris skips 02:30 on 29 March, New York does not.
        let args = json!({"title": "M", "start": "2026-03-29T02:30:00", "end": "2026-03-29T03:00:00",
            "time_zone": "America/New_York"});
        let resolved = resolve_event_times(&args, Some("Europe/Paris")).unwrap();
        assert_eq!(resolved["start_utc"], "20260329T063000Z");
        let mut paris = args.clone();
        paris["time_zone"] = json!("Europe/Paris");
        let err = resolve_event_times(&paris, Some("America/New_York")).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn repeated_unreadable_and_backwards_times_are_refused_without_echo() {
        for (start, end, why) in [
            (
                "2026-10-25T02:30:00",
                "2026-10-25T04:00:00",
                "happens twice",
            ),
            ("tomorrow 10:00", "2026-10-26T11:00:00", "not a local date"),
            ("2026-10-26T10:00:00", "2026-10-26T09:00:00", "ends before"),
        ] {
            let args =
                json!({"title": "M", "start": start, "end": end, "time_zone": "Europe/Paris"});
            let err = resolve_event_times(&args, None).unwrap_err();
            assert!(err.contains(why) && !err.contains(start), "{start}: {err}");
        }
        // The repeated hour is accepted once its offset picks one of the two.
        let mut picked = json!({"title": "M", "start": "2026-10-25T02:30:00+01:00", "time_zone": "Europe/Paris"});
        let resolved = resolve_event_times(&picked, None).unwrap();
        assert_eq!(resolved["start_utc"], "20261025T013000Z");
        picked["attendee_time_zone"] = json!("Camille Exemple");
        let err = resolve_event_times(&picked, None).unwrap_err();
        assert!(
            err.contains("unknown time zone") && !err.contains("Camille"),
            "{err}"
        );
    }

    #[test]
    fn a_stored_client_zone_replaces_the_models_and_says_so() {
        // 10:00 in Paris is 09:00 UTC, which is 18:00 in Tokyo, not 05:00 in
        // New York. The client card's zone decides; the model's note stays.
        let args = json!({"title": "M", "start": "2026-10-26T10:00:00",
            "end": "2026-10-26T10:30:00", "time_zone": "Europe/Paris",
            "attendee_time_zone": "America/New_York"});
        let resolved =
            resolve_event_times_for_client(&args, Some("Europe/Paris"), Some("Asia/Tokyo"))
                .unwrap();
        assert_eq!(resolved["attendee_time_zone"], "Asia/Tokyo");
        assert_eq!(resolved["attendee_start"], "2026-10-26T18:00:00+09:00");
        let source = resolved["attendee_time_zone_source"].as_str().unwrap();
        assert!(
            source.contains("client card") && source.contains("America/New_York"),
            "{source}"
        );
        // Idempotent: resolving the card's arguments again changes nothing.
        assert_eq!(
            resolve_event_times_for_client(&resolved, Some("Europe/Paris"), Some("Asia/Tokyo"))
                .unwrap(),
            resolved
        );
        // No stored zone, or a stored offset that is not one, keeps the
        // model's argument exactly as before.
        for stored in [None, Some("-05:00"), Some("Mars/Olympus")] {
            let fallback =
                resolve_event_times_for_client(&args, Some("Europe/Paris"), stored).unwrap();
            assert_eq!(fallback["attendee_time_zone"], "America/New_York");
            assert_eq!(fallback["attendee_start"], "2026-10-26T05:00:00-04:00");
            assert!(fallback.get("attendee_time_zone_source").is_none());
        }
        // A client card zone with no model zone gets the plain note.
        let mut no_model = args.clone();
        no_model
            .as_object_mut()
            .unwrap()
            .remove("attendee_time_zone");
        let resolved =
            resolve_event_times_for_client(&no_model, Some("Europe/Paris"), Some("Asia/Tokyo"))
                .unwrap();
        assert_eq!(resolved["attendee_time_zone_source"], "client card");
    }
}
