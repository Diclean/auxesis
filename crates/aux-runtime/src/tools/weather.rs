//! `weather_forecast` and `weather_geocode` — read-only weather from Open-Meteo.
//!
//! Two native tools over the public Open-Meteo APIs, which need no key. They
//! are adapters over [`aux_runtime::fetch::Fetcher`] built from `[web]`, so every
//! request goes through the same deterministic gate as `http_fetch`: public
//! addresses only (SSRF guard), `deny_domains`, scheme and port rules, URL and
//! query caps, and the body and time caps. Redirects are switched off, so a
//! request can only be answered by the host it named.
//!
//! What leaves the machine is a place name (letters, spaces and `-'.,` only,
//! at most [`MAX_PLACE_BYTES`] bytes) or two coordinates, sent to the two fixed
//! hosts below. The model never supplies a URL or a host.
//!
//! Both tools declare [`Tool::performs_web_egress`] and are not registered as
//! read-only: the place name is text the model chooses, so each call asks the
//! owner unless an allow rule covers it.
//!
//! TODO: owner rule "every MCP gets data_class, missing = sensitive". No
//! `data_class` concept exists in the registry yet, so nothing is set here.
//! These are native tools, not MCP servers; their output is public weather
//! data and the outbound payload is the place name or coordinates only.

use crate::fetch::Fetcher;
use async_trait::async_trait;
use kernel_broker::ToolClass;
use kernel_broker::{
    sanitize_external_text, NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput,
};
use kernel_core::WebConfig;
use kernel_net::{FetchError, RenderMode, UNTRUSTED_TAG};
use serde::Deserialize;
use serde_json::{json, Value};

/// Current conditions and daily forecast. Open-Meteo, no key.
const FORECAST_URL: &str = "https://api.open-meteo.com/v1/forecast";
/// Place name to coordinates. Open-Meteo, no key.
const GEOCODE_URL: &str = "https://geocoding-api.open-meteo.com/v1/search";
const FORECAST_HOSTS: &[&str] = &["api.open-meteo.com"];
const GEOCODE_HOSTS: &[&str] = &["geocoding-api.open-meteo.com"];
const PLACE_FORECAST_HOSTS: &[&str] = &["geocoding-api.open-meteo.com", "api.open-meteo.com"];
/// Longest place name accepted, in UTF-8 bytes. Every byte percent-encodes to
/// at most three characters, so the encoded geocoding query stays well under
/// the default `[web]` query cap of 256 bytes.
const MAX_PLACE_BYTES: usize = 64;
const MAX_FORECAST_DAYS: i64 = 7;
const DEFAULT_FORECAST_DAYS: i64 = 3;
/// Candidates returned by `weather_geocode`; `weather_forecast` asks for one.
const GEOCODE_CANDIDATES: u8 = 5;
/// Largest JSON answer accepted from either host. A 7-day answer is a few KB.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Requested in metric only. Imperial is converted locally, so the query never
/// grows past the `[web]` query cap.
const CURRENT_FIELDS: &str = "temperature_2m,weather_code,wind_speed_10m";
const DAILY_FIELDS: &str =
    "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// `weather_forecast`: current conditions and a daily forecast for a place name
/// or for coordinates.
pub struct WeatherForecastTool {
    fetcher: Fetcher,
}

impl WeatherForecastTool {
    /// The production tool, configured from `[web]`.
    pub fn with_web(web: WebConfig) -> Self {
        Self {
            fetcher: fetcher_for(web),
        }
    }
}

/// `weather_geocode`: candidate places for a name.
pub struct WeatherGeocodeTool {
    fetcher: Fetcher,
}

impl WeatherGeocodeTool {
    /// The production tool, configured from `[web]`.
    pub fn with_web(web: WebConfig) -> Self {
        Self {
            fetcher: fetcher_for(web),
        }
    }
}

/// The `[web]` gate with redirects switched off: the answer must come from the
/// host the request named, never from a hop the gate did not check.
fn fetcher_for(mut web: WebConfig) -> Fetcher {
    web.max_redirects = 0;
    Fetcher::with_web(web)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Units {
    #[default]
    Metric,
    Imperial,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForecastArgs {
    place: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    days: Option<i64>,
    units: Option<Units>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeocodeArgs {
    name: String,
}

const WEATHER_FORECAST_DESCRIPTION: &str = "Current weather and a daily forecast for a place name or for coordinates, from Open-Meteo (free, no key). Read-only: it sends only the place name or the two coordinates. Metric by default (°C, km/h, mm).";

impl NativeTool for WeatherForecastTool {
    fn native_name(&self) -> &'static str {
        "weather_forecast"
    }

    fn native_description(&self) -> &'static str {
        WEATHER_FORECAST_DESCRIPTION
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            json!({
                "type": "object",
                "description": WEATHER_FORECAST_DESCRIPTION,
                "properties": {
                    "place": {
                        "type": "string",
                        "description": "Place name such as \"Lyon\" or \"Paris, France\" (letters, spaces and - ' . , only; at most 64 bytes). Give this or latitude and longitude, not both."
                    },
                    "latitude": {"type": "number", "minimum": -90, "maximum": 90},
                    "longitude": {"type": "number", "minimum": -180, "maximum": 180},
                    "days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 7,
                        "description": "Days to forecast, today included (default 3)."
                    },
                    "units": {
                        "type": "string",
                        "enum": ["metric", "imperial"],
                        "description": "metric (default): °C, km/h, mm. imperial: °F, mph, in."
                    }
                },
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for WeatherForecastTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B7
    }
    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: ForecastArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let days = args.days.unwrap_or(DEFAULT_FORECAST_DAYS);
        if !(1..=MAX_FORECAST_DAYS).contains(&days) {
            return Err(ToolError::invalid_args(
                self.name(),
                format!("days must be between 1 and {MAX_FORECAST_DAYS}"),
            ));
        }
        let units = args.units.unwrap_or_default();
        let target = resolve_target(args.place, args.latitude, args.longitude)
            .map_err(|message| ToolError::invalid_args(self.name(), message))?;

        let private = ctx
            .grant()
            .is_some_and(|grant| grant.mode() == kernel_core::privacy::PrivacyMode::Private);
        let place = match target {
            Target::Place(name) => match geocode(&self.fetcher, &name, ctx.egress.as_ref()).await {
                Ok(mut found) if !found.is_empty() => found.swap_remove(0),
                Ok(_) => return Ok(ToolOutput::error(format!("No place found for “{name}”."))),
                Err(message) => return Ok(ToolOutput::error(message)),
            },
            Target::Coordinates {
                latitude,
                longitude,
            } => {
                let (latitude, longitude) = if private {
                    (round_coordinate(latitude), round_coordinate(longitude))
                } else {
                    (latitude, longitude)
                };
                Place::at(latitude, longitude)
            }
        };

        let url = forecast_url_for_mode(place.latitude, place.longitude, days, private);
        let text = match get_json(&self.fetcher, &url, ctx.egress.as_ref()).await {
            Ok(text) => text,
            Err(message) => return Ok(ToolOutput::error(message)),
        };
        match forecast_value(&text, place, units) {
            Ok(value) => Ok(ToolOutput::ok(render(&value))),
            Err(message) => Ok(ToolOutput::error(message)),
        }
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn egress_hosts(&self, arguments: &Value) -> &'static [&'static str] {
        if arguments.get("place").and_then(Value::as_str).is_some() {
            PLACE_FORECAST_HOSTS
        } else {
            FORECAST_HOSTS
        }
    }

    /// The place name as validated, or the coordinates as they are sent.
    fn egress_query(&self, arguments: &Value) -> Option<String> {
        let args: ForecastArgs = serde_json::from_value(arguments.clone()).ok()?;
        match resolve_target(args.place, args.latitude, args.longitude).ok()? {
            Target::Place(name) => Some(name),
            Target::Coordinates {
                latitude,
                longitude,
            } => Some(format!("{latitude:.4}, {longitude:.4}")),
        }
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: // Public forecast data; the place name is the only owner input.
        false,
            performs_web_egress: true,
            ..ToolClass::default()
        }
    }
}

const WEATHER_GEOCODE_DESCRIPTION: &str = "Find places matching a name, from Open-Meteo geocoding (free, no key). Returns up to 5 candidates with coordinates, region, country and timezone. Read-only: it sends only the name.";

impl NativeTool for WeatherGeocodeTool {
    fn native_name(&self) -> &'static str {
        "weather_geocode"
    }

    fn native_description(&self) -> &'static str {
        WEATHER_GEOCODE_DESCRIPTION
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            json!({
                "type": "object",
                "description": WEATHER_GEOCODE_DESCRIPTION,
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Place name, as for weather_forecast (letters, spaces and - ' . , only; at most 64 bytes)."
                    }
                },
                "required": ["name"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for WeatherGeocodeTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B7
    }
    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: GeocodeArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let name = validate_place(&args.name)
            .map_err(|message| ToolError::invalid_args(self.name(), message))?;
        match geocode(&self.fetcher, &name, ctx.egress.as_ref()).await {
            Ok(places) => {
                let results: Vec<Value> = places.iter().map(Place::to_json).collect();
                Ok(ToolOutput::ok(render(&json!({ "results": results }))))
            }
            Err(message) => Ok(ToolOutput::error(message)),
        }
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn egress_hosts(&self, _arguments: &Value) -> &'static [&'static str] {
        GEOCODE_HOSTS
    }

    /// The place name as validated.
    fn egress_query(&self, arguments: &Value) -> Option<String> {
        let args: GeocodeArgs = serde_json::from_value(arguments.clone()).ok()?;
        validate_place(&args.name).ok()
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: // Public geocoding of a named place; no owner data in the result.
        false,
            performs_web_egress: true,
            ..ToolClass::default()
        }
    }
}

/// What a forecast is for: a place name to look up, or coordinates as given.
#[derive(Debug, PartialEq)]
enum Target {
    Place(String),
    Coordinates { latitude: f64, longitude: f64 },
}

fn resolve_target(
    place: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> Result<Target, String> {
    match (place, latitude, longitude) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            Err("give either place or latitude and longitude, not both".to_string())
        }
        (Some(place), None, None) => Ok(Target::Place(validate_place(&place)?)),
        (None, Some(latitude), Some(longitude)) => {
            validate_coordinates(latitude, longitude)?;
            Ok(Target::Coordinates {
                latitude,
                longitude,
            })
        }
        (None, None, None) => Err("give a place, or latitude and longitude".to_string()),
        _ => Err("latitude and longitude must be given together".to_string()),
    }
}

/// A place name is letters, spaces and `- ' ’ . ,`, at least one letter, at
/// most [`MAX_PLACE_BYTES`] bytes. Digits and everything else are refused, so
/// the outbound text cannot carry numbers or markup. A private session token
/// (`⟦PERSON_1A2B⟧`) is the one exception: it is the masked form of a personal
/// value and goes out as the token, never as the value (TOK-3).
fn validate_place(raw: &str) -> Result<String, String> {
    let place = raw.trim();
    if place.is_empty() {
        return Err("place is empty".to_string());
    }
    if place.len() > MAX_PLACE_BYTES {
        return Err(format!("place is longer than {MAX_PLACE_BYTES} bytes"));
    }
    let allowed = |c: char| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | '’' | '.' | ',');
    let plain = mask_tokens(place);
    if !plain.chars().all(allowed) {
        return Err("place may contain only letters, spaces and - ' ’ . ,".to_string());
    }
    if !plain.chars().any(char::is_alphabetic) {
        return Err("place needs at least one letter".to_string());
    }
    Ok(place.to_string())
}

/// `text` with each well-formed session token (`⟦KIND_HEX⟧`) replaced by one
/// letter, so the character check sees the token as a name.
fn mask_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('⟦') {
        out.push_str(&rest[..open]);
        let after = &rest[open + '⟦'.len_utf8()..];
        match after.find('⟧') {
            Some(end)
                if end > 0
                    && after[..end]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_') =>
            {
                out.push('T');
                rest = &after[end + '⟧'.len_utf8()..];
            }
            _ => {
                out.push('⟦');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn validate_coordinates(latitude: f64, longitude: f64) -> Result<(), String> {
    if !(-90.0..=90.0).contains(&latitude) {
        return Err("latitude must be between -90 and 90".to_string());
    }
    if !(-180.0..=180.0).contains(&longitude) {
        return Err("longitude must be between -180 and 180".to_string());
    }
    Ok(())
}

/// RFC 3986 percent-encoding of everything outside the unreserved set.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0F)]));
            }
        }
    }
    out
}

fn forecast_url(latitude: f64, longitude: f64, days: i64) -> String {
    format!(
        "{FORECAST_URL}?latitude={latitude:.4}&longitude={longitude:.4}&current={CURRENT_FIELDS}&daily={DAILY_FIELDS}&timezone=auto&forecast_days={days}"
    )
}

fn forecast_url_for_mode(latitude: f64, longitude: f64, days: i64, private: bool) -> String {
    let (latitude, longitude) = if private {
        (round_coordinate(latitude), round_coordinate(longitude))
    } else {
        (latitude, longitude)
    };
    forecast_url(latitude, longitude, days)
}

fn round_coordinate(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn geocode_url(name: &str) -> String {
    format!(
        "{GEOCODE_URL}?name={}&count={GEOCODE_CANDIDATES}",
        percent_encode(name)
    )
}

/// Fetch `url` through the `[web]` gate and return the JSON text. Every failure
/// is a message the model can read; nothing here carries the URL or the place
/// name back out.
async fn get_json(
    fetcher: &Fetcher,
    url: &str,
    egress: Option<&kernel_net::FetchEgress>,
) -> Result<String, String> {
    let result = match egress {
        Some(egress) => {
            fetcher
                .fetch_with_egress(url, RenderMode::Simple, egress)
                .await
        }
        None => fetcher.fetch(url, RenderMode::Simple).await,
    };
    match result {
        Ok(page) if page.truncated || page.text.len() > MAX_RESPONSE_BYTES => {
            Err("the Open-Meteo answer was too large".to_string())
        }
        Ok(page) => Ok(page.text),
        Err(FetchError::HttpStatus { status, body, .. }) => Err(http_error_message(status, &body)),
        Err(FetchError::PolicyRefused(_) | FetchError::RedirectNeedsApproval { .. }) => {
            Err("the request was refused by the web egress policy".to_string())
        }
        Err(FetchError::Timeout { seconds }) => {
            Err(format!("Open-Meteo did not answer within {seconds} s"))
        }
        Err(_) => Err("could not reach Open-Meteo".to_string()),
    }
}

async fn geocode(
    fetcher: &Fetcher,
    name: &str,
    egress: Option<&kernel_net::FetchEgress>,
) -> Result<Vec<Place>, String> {
    let text = get_json(fetcher, &geocode_url(name), egress).await?;
    parse_geocode(&text)
}

/// A resolved location, as the model sees it.
#[derive(Debug, Clone, PartialEq)]
struct Place {
    name: Option<String>,
    region: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    latitude: f64,
    longitude: f64,
    timezone: Option<String>,
}

impl Place {
    /// Coordinates the owner gave directly: no name, no region.
    fn at(latitude: f64, longitude: f64) -> Self {
        Self {
            name: None,
            region: None,
            country: None,
            country_code: None,
            latitude,
            longitude,
            timezone: None,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name.as_deref().map(external),
            "region": self.region.as_deref().map(external),
            "country": self.country.as_deref().map(external),
            "country_code": self.country_code.as_deref().map(external),
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone.as_deref().map(external),
        })
    }
}

/// Text that came from Open-Meteo is third-party data: strip control and
/// invisible characters and cap its length before it reaches the model.
fn external(text: &str) -> String {
    sanitize_external_text(text, 128)
}

#[derive(Debug, Deserialize)]
struct GeocodeBody {
    results: Option<Vec<GeocodeHit>>,
}

#[derive(Debug, Deserialize)]
struct GeocodeHit {
    name: String,
    latitude: f64,
    longitude: f64,
    admin1: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    timezone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ForecastBody {
    timezone: Option<String>,
    current: CurrentBody,
    daily: DailyBody,
}

#[derive(Debug, Deserialize)]
struct CurrentBody {
    time: String,
    weather_code: Option<f64>,
    temperature_2m: Option<f64>,
    wind_speed_10m: Option<f64>,
}

/// Daily series arrive as parallel arrays with `null` for a missing day.
#[derive(Debug, Deserialize)]
struct DailyBody {
    time: Vec<String>,
    weather_code: Option<Vec<Option<f64>>>,
    temperature_2m_max: Option<Vec<Option<f64>>>,
    temperature_2m_min: Option<Vec<Option<f64>>>,
    precipitation_sum: Option<Vec<Option<f64>>>,
    wind_speed_10m_max: Option<Vec<Option<f64>>>,
}

/// Open-Meteo reports request errors as `{"error": true, "reason": "..."}`.
fn api_error(value: &Value) -> Option<String> {
    if value.get("error").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let reason = value
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("no reason given");
    Some(format!(
        "Open-Meteo rejected the request: {}",
        external(reason)
    ))
}

/// The message for a non-success answer. Open-Meteo states its reason in a
/// JSON body (`{"error":true,"reason":...}`); that reason is shown only when
/// the body says so, and it is sanitised like any third-party text.
fn http_error_message(status: u16, body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .as_ref()
        .and_then(api_error)
        .unwrap_or_else(|| format!("Open-Meteo answered HTTP {status}"))
}

fn malformed(err: impl std::fmt::Display) -> String {
    format!("the Open-Meteo answer could not be read: {err}")
}

/// Candidate places from a geocoding answer. No `results` key means no match.
fn parse_geocode(text: &str) -> Result<Vec<Place>, String> {
    let value: Value = serde_json::from_str(text).map_err(malformed)?;
    if let Some(message) = api_error(&value) {
        return Err(message);
    }
    let body: GeocodeBody = serde_json::from_value(value).map_err(malformed)?;
    Ok(body
        .results
        .unwrap_or_default()
        .into_iter()
        .map(|hit| Place {
            name: Some(hit.name),
            region: hit.admin1,
            country: hit.country,
            country_code: hit.country_code,
            latitude: hit.latitude,
            longitude: hit.longitude,
            timezone: hit.timezone,
        })
        .collect())
}

/// The forecast object: place, units, current conditions and a daily list.
fn forecast_value(text: &str, mut place: Place, units: Units) -> Result<Value, String> {
    let value: Value = serde_json::from_str(text).map_err(malformed)?;
    if let Some(message) = api_error(&value) {
        return Err(message);
    }
    let body: ForecastBody = serde_json::from_value(value).map_err(malformed)?;
    if body.timezone.is_some() {
        place.timezone = body.timezone;
    }
    let daily = &body.daily;
    let days: Vec<Value> = daily
        .time
        .iter()
        .enumerate()
        .map(|(index, date)| {
            json!({
                "date": external(date),
                "condition": weather_label(at(&daily.weather_code, index)),
                "temperature_min": temperature(at(&daily.temperature_2m_min, index), units),
                "temperature_max": temperature(at(&daily.temperature_2m_max, index), units),
                "precipitation_sum": precipitation(at(&daily.precipitation_sum, index), units),
                "wind_speed_max": wind(at(&daily.wind_speed_10m_max, index), units),
            })
        })
        .collect();
    let current = &body.current;
    Ok(json!({
        "place": place.to_json(),
        "units": units_json(units),
        "current": {
            "time": external(&current.time),
            "condition": weather_label(current.weather_code),
            "temperature": temperature(current.temperature_2m, units),
            "wind_speed": wind(current.wind_speed_10m, units),
        },
        "daily": days,
    }))
}

fn at(series: &Option<Vec<Option<f64>>>, index: usize) -> Option<f64> {
    series
        .as_ref()
        .and_then(|values| values.get(index).copied().flatten())
}

fn units_json(units: Units) -> Value {
    match units {
        Units::Metric => json!({"temperature": "°C", "wind_speed": "km/h", "precipitation": "mm"}),
        Units::Imperial => json!({"temperature": "°F", "wind_speed": "mph", "precipitation": "in"}),
    }
}

fn round_to(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

/// Open-Meteo answers in metric; imperial is converted here.
fn temperature(celsius: Option<f64>, units: Units) -> Option<f64> {
    celsius.map(|c| match units {
        Units::Metric => round_to(c, 1),
        Units::Imperial => round_to(c * 9.0 / 5.0 + 32.0, 1),
    })
}

fn wind(kmh: Option<f64>, units: Units) -> Option<f64> {
    kmh.map(|v| match units {
        Units::Metric => round_to(v, 1),
        Units::Imperial => round_to(v * 0.621_371, 1),
    })
}

fn precipitation(mm: Option<f64>, units: Units) -> Option<f64> {
    mm.map(|v| match units {
        Units::Metric => round_to(v, 1),
        Units::Imperial => round_to(v * 0.039_370_1, 2),
    })
}

/// English labels for the WMO weather codes Open-Meteo returns.
fn weather_label(code: Option<f64>) -> &'static str {
    let Some(code) = code else {
        return "unknown";
    };
    let rounded = code.round();
    if (code - rounded).abs() > 1e-9 {
        return "unknown";
    }
    match rounded as i64 {
        0 => "clear sky",
        1 => "mainly clear",
        2 => "partly cloudy",
        3 => "overcast",
        45 => "fog",
        48 => "depositing rime fog",
        51 => "light drizzle",
        53 => "moderate drizzle",
        55 => "dense drizzle",
        56 => "light freezing drizzle",
        57 => "dense freezing drizzle",
        61 => "slight rain",
        63 => "moderate rain",
        65 => "heavy rain",
        66 => "light freezing rain",
        67 => "heavy freezing rain",
        71 => "slight snow fall",
        73 => "moderate snow fall",
        75 => "heavy snow fall",
        77 => "snow grains",
        80 => "slight rain showers",
        81 => "moderate rain showers",
        82 => "violent rain showers",
        85 => "slight snow showers",
        86 => "heavy snow showers",
        95 => "thunderstorm",
        96 => "thunderstorm with slight hail",
        99 => "thunderstorm with heavy hail",
        _ => "unknown",
    }
}

/// Model-facing text: the untrusted-content tag, then compact JSON.
fn render(value: &Value) -> String {
    format!("{UNTRUSTED_TAG} source: open-meteo.com\n{value}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::ToolClassExt;
    use kernel_broker::Trust;

    const GEOCODE_PARIS: &str = include_str!("../../tests/fixtures/open-meteo/geocode-paris.json");
    const GEOCODE_UNKNOWN: &str =
        include_str!("../../tests/fixtures/open-meteo/geocode-unknown.json");
    const FORECAST_PARIS: &str =
        include_str!("../../tests/fixtures/open-meteo/forecast-paris.json");
    const FORECAST_BAD_LATITUDE: &str =
        include_str!("../../tests/fixtures/open-meteo/forecast-bad-latitude.json");

    /// The default `[web] max_query_bytes`.
    const QUERY_CAP: usize = 256;

    fn query_of(url: &str) -> &str {
        url.split_once('?').map(|(_, query)| query).unwrap_or("")
    }

    #[test]
    fn place_names_are_letters_spaces_and_name_punctuation_only() {
        for ok in [
            "Paris",
            "Saint-Étienne",
            "L'Aquila",
            "Paris, France",
            "São Paulo",
        ] {
            assert_eq!(validate_place(ok).as_deref(), Ok(ok), "{ok}");
        }
        assert_eq!(validate_place("  Lyon  ").as_deref(), Ok("Lyon"));
        for bad in [
            "",
            "   ",
            "123",
            "Paris 75",
            "a@b.fr",
            "Paris\nSecret",
            "Lyon;rm",
        ] {
            assert!(validate_place(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn place_names_over_the_byte_budget_are_refused() {
        let at_limit = format!("{}a", "’".repeat(21));
        assert_eq!(at_limit.len(), MAX_PLACE_BYTES);
        assert!(validate_place(&at_limit).is_ok());
        assert!(validate_place(&format!("{at_limit}a")).is_err());
    }

    #[test]
    fn place_arguments_that_look_like_pii_are_refused() {
        let too_long = format!("A{}", "b".repeat(100));
        for candidate in ["owner@example.test", "+1 (555) 010-2040", too_long.as_str()] {
            assert!(
                validate_place(candidate).is_err(),
                "PII-like place argument must be refused: {candidate:?}"
            );
        }
        assert!(too_long.len() > 100);
    }

    #[test]
    fn percent_encoding_is_rfc3986() {
        assert_eq!(percent_encode("Saint-Étienne"), "Saint-%C3%89tienne");
        assert_eq!(percent_encode("Paris, France"), "Paris%2C%20France");
        assert_eq!(percent_encode("L'Aquila"), "L%27Aquila");
        assert_eq!(percent_encode("a.b_c~d-e"), "a.b_c~d-e");
    }

    #[test]
    fn urls_name_only_the_two_open_meteo_hosts() {
        let forecast = forecast_url(48.85341, 2.3488, 3);
        assert!(forecast.starts_with("https://api.open-meteo.com/v1/forecast?"));
        assert!(forecast.contains("latitude=48.8534&longitude=2.3488&"));
        assert!(forecast.ends_with("timezone=auto&forecast_days=3"));
        let geocode = geocode_url("Paris, France");
        assert_eq!(
            geocode,
            "https://geocoding-api.open-meteo.com/v1/search?name=Paris%2C%20France&count=5"
        );
    }

    #[test]
    fn private_coordinate_url_uses_ten_kilometre_precision() {
        let exact = (48.85341, 2.3488);
        let url = forecast_url_for_mode(exact.0, exact.1, 3, true);
        assert!(url.contains("latitude=48.9000&longitude=2.3000&"), "{url}");
        assert!(!url.contains("48.85341"), "{url}");
        assert!(!url.contains("2.3488"), "{url}");
    }

    #[test]
    fn the_worst_case_queries_fit_the_default_query_cap() {
        // Seven days, the most negative coordinates, metric: the longest forecast.
        let forecast = forecast_url(-90.0, -180.0, 7);
        assert!(query_of(&forecast).len() <= QUERY_CAP, "{forecast}");
        // A full 64-byte place made of the widest-encoding characters.
        let name = "’".repeat(21) + "a";
        let geocode = geocode_url(&name);
        assert!(query_of(&geocode).len() <= QUERY_CAP, "{geocode}");
        assert!(geocode.len() <= 512, "the default max_url_bytes");
    }

    #[test]
    fn targets_are_exactly_one_of_place_or_coordinates() {
        assert_eq!(
            resolve_target(Some("Lyon".into()), None, None),
            Ok(Target::Place("Lyon".into()))
        );
        assert_eq!(
            resolve_target(None, Some(45.75), Some(4.85)),
            Ok(Target::Coordinates {
                latitude: 45.75,
                longitude: 4.85
            })
        );
        assert!(resolve_target(Some("Lyon".into()), Some(45.75), Some(4.85)).is_err());
        assert!(resolve_target(Some("Lyon".into()), Some(45.75), None).is_err());
        assert!(resolve_target(None, Some(45.75), None).is_err());
        assert!(resolve_target(None, None, None).is_err());
        assert!(resolve_target(None, Some(91.0), Some(0.0)).is_err());
        assert!(resolve_target(None, Some(0.0), Some(-180.5)).is_err());
    }

    #[test]
    fn geocode_fixture_lists_the_candidates_in_order() {
        let places = parse_geocode(GEOCODE_PARIS).expect("fixture parses");
        assert_eq!(places.len(), 5);
        let first = &places[0];
        assert_eq!(first.name.as_deref(), Some("Paris"));
        assert_eq!(first.region.as_deref(), Some("Île-de-France Region"));
        assert_eq!(first.country.as_deref(), Some("France"));
        assert_eq!(first.country_code.as_deref(), Some("FR"));
        assert_eq!(first.timezone.as_deref(), Some("Europe/Paris"));
        assert!((first.latitude - 48.85341).abs() < 1e-9);
        assert!((first.longitude - 2.3488).abs() < 1e-9);
    }

    #[test]
    fn an_unknown_place_is_an_empty_list_not_an_error() {
        assert_eq!(parse_geocode(GEOCODE_UNKNOWN), Ok(Vec::new()));
        assert_eq!(parse_geocode(r#"{"results":[]}"#), Ok(Vec::new()));
    }

    #[test]
    fn a_geocoding_api_error_is_reported_with_its_reason() {
        let err = parse_geocode(r#"{"error":true,"reason":"Parameter 'name' must not be empty"}"#)
            .unwrap_err();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn a_geocoding_answer_that_is_not_json_is_an_error() {
        assert!(parse_geocode("<html>gateway</html>")
            .unwrap_err()
            .contains("could not be read"));
        assert!(parse_geocode(r#"{"results":[{"name":"X"}]}"#).is_err());
    }

    #[test]
    fn forecast_fixture_maps_current_and_daily_in_metric() {
        let place = Place::at(48.85341, 2.3488);
        let value = forecast_value(FORECAST_PARIS, place, Units::Metric).expect("fixture parses");
        assert_eq!(value["place"]["timezone"], "Europe/Paris");
        assert_eq!(value["place"]["name"], Value::Null);
        assert_eq!(value["units"]["temperature"], "°C");
        assert_eq!(value["current"]["condition"], "partly cloudy");
        assert_eq!(value["current"]["temperature"], 9.9);
        assert_eq!(value["current"]["wind_speed"], 4.3);
        let days = value["daily"].as_array().expect("daily list");
        assert_eq!(days.len(), 3);
        assert_eq!(days[0]["date"], "2026-10-09");
        assert_eq!(days[0]["condition"], "slight rain");
        assert_eq!(days[0]["temperature_min"], 9.9);
        assert_eq!(days[0]["temperature_max"], 15.9);
        assert_eq!(days[0]["precipitation_sum"], 0.1);
        assert_eq!(days[0]["wind_speed_max"], 13.4);
        assert_eq!(days[1]["condition"], "slight rain showers");
    }

    #[test]
    fn forecast_fixture_converts_to_imperial_locally() {
        let place = Place::at(48.85341, 2.3488);
        let value = forecast_value(FORECAST_PARIS, place, Units::Imperial).expect("fixture parses");
        assert_eq!(value["units"]["temperature"], "°F");
        assert_eq!(value["units"]["wind_speed"], "mph");
        assert_eq!(value["current"]["temperature"], 49.8); // 9.9 °C
        assert_eq!(value["current"]["wind_speed"], 2.7); // 4.3 km/h
        assert_eq!(value["daily"][0]["temperature_max"], 60.6); // 15.9 °C
        assert_eq!(value["daily"][0]["wind_speed_max"], 8.3); // 13.4 km/h
    }

    #[test]
    fn forecast_api_error_is_reported_with_its_reason() {
        let err =
            forecast_value(FORECAST_BAD_LATITUDE, Place::at(0.0, 0.0), Units::Metric).unwrap_err();
        assert!(err.contains("Latitude must be in range"), "{err}");
    }

    #[test]
    fn a_forecast_missing_its_daily_block_is_an_error() {
        let text = r#"{"current":{"time":"2026-10-09T12:00","temperature_2m":10.0}}"#;
        assert!(forecast_value(text, Place::at(0.0, 0.0), Units::Metric).is_err());
        assert!(forecast_value("[]", Place::at(0.0, 0.0), Units::Metric).is_err());
    }

    #[test]
    fn missing_values_stay_null_and_do_not_shift_the_days() {
        let text = r#"{
            "timezone": "Europe/Paris",
            "current": {"time": "2026-10-09T12:00", "weather_code": 0, "temperature_2m": null},
            "daily": {
                "time": ["2026-10-09", "2026-10-10"],
                "temperature_2m_max": [null, 12.0],
                "temperature_2m_min": [3.0, 4.0]
            }
        }"#;
        let value = forecast_value(text, Place::at(1.0, 1.0), Units::Metric).unwrap();
        assert_eq!(value["current"]["temperature"], Value::Null);
        assert_eq!(value["current"]["condition"], "clear sky");
        assert_eq!(value["daily"][0]["temperature_max"], Value::Null);
        assert_eq!(value["daily"][0]["temperature_min"], 3.0);
        assert_eq!(value["daily"][1]["temperature_max"], 12.0);
        assert_eq!(value["daily"][1]["precipitation_sum"], Value::Null);
    }

    #[test]
    fn wmo_codes_map_to_labels_and_unknown_codes_say_so() {
        assert_eq!(weather_label(Some(0.0)), "clear sky");
        assert_eq!(weather_label(Some(95.0)), "thunderstorm");
        assert_eq!(weather_label(Some(1234.0)), "unknown");
        assert_eq!(weather_label(Some(2.5)), "unknown");
        assert_eq!(weather_label(None), "unknown");
    }

    #[test]
    fn third_party_place_text_is_sanitised_before_the_model_sees_it() {
        let place = Place {
            name: Some("Par\u{1b}[31mis\u{200b}".to_string()),
            ..Place::at(1.0, 1.0)
        };
        let rendered = place.to_json().to_string();
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
        assert!(!rendered.contains('\u{200b}'), "{rendered}");
        assert!(rendered.contains("Par"), "{rendered}");
    }

    #[test]
    fn rendered_answers_carry_the_untrusted_tag() {
        assert!(render(&json!({})).starts_with(UNTRUSTED_TAG));
    }

    #[test]
    fn the_tools_are_closed_schemas_and_declare_their_class() {
        let web = WebConfig::default();
        let forecast = WeatherForecastTool::with_web(web.clone());
        let geocode = WeatherGeocodeTool::with_web(web);
        for tool in [&forecast as &dyn Tool, &geocode as &dyn Tool] {
            assert_eq!(tool.schema()["additionalProperties"], false);
            assert!(tool.performs_web_egress());
            assert!(!tool.returns_private_data());
            assert_eq!(tool.risk(), Risk::Low);
            assert_eq!(tool.output_trust(), Trust::Untrusted);
        }
        assert_eq!(geocode.schema()["required"], json!(["name"]));
        assert_eq!(forecast.name(), "weather_forecast");
        assert_eq!(geocode.name(), "weather_geocode");
        assert_eq!(
            forecast.egress_hosts(&json!({ "place": "Paris" })),
            &["geocoding-api.open-meteo.com", "api.open-meteo.com"]
        );
        assert_eq!(
            forecast.egress_hosts(&json!({ "latitude": 48.8, "longitude": 2.3 })),
            &["api.open-meteo.com"]
        );
        assert_eq!(
            geocode.egress_hosts(&json!({ "name": "Paris" })),
            &["geocoding-api.open-meteo.com"]
        );
    }

    #[test]
    fn a_rejected_request_states_its_reason_from_the_400_body() {
        let body =
            r#"{"error":true,"reason":"Latitude must be in range of -90 to 90. Given: 123.0."}"#;
        assert_eq!(
            http_error_message(400, body),
            "Open-Meteo rejected the request: Latitude must be in range of -90 to 90. Given: 123.0."
        );
        // Without the reason, or with a body that is not Open-Meteo's, the
        // answer keeps the plain status.
        assert_eq!(
            http_error_message(502, "<html>bad gateway</html>"),
            "Open-Meteo answered HTTP 502"
        );
        assert_eq!(
            http_error_message(400, r#"{"error":false}"#),
            "Open-Meteo answered HTTP 400"
        );
    }

    #[test]
    fn the_declared_text_is_the_validated_place_or_the_coordinates() {
        let forecast = WeatherForecastTool::with_web(WebConfig::default());
        assert_eq!(
            forecast
                .egress_query(&json!({ "place": "  Paris " }))
                .as_deref(),
            Some("Paris")
        );
        assert_eq!(
            forecast
                .egress_query(&json!({ "latitude": 48.85, "longitude": 2.35 }))
                .as_deref(),
            Some("48.8500, 2.3500")
        );
        // A refused place sends nothing the card could show as text.
        assert_eq!(forecast.egress_query(&json!({ "place": "Paris 75" })), None);
        let geocode = WeatherGeocodeTool::with_web(WebConfig::default());
        assert_eq!(
            geocode.egress_query(&json!({ "name": "Lyon" })).as_deref(),
            Some("Lyon")
        );
    }

    #[test]
    fn a_session_token_goes_out_as_the_token_in_the_place_and_in_the_query() {
        let token = "⟦PERSON_8F2193E4E90C⟧";
        assert_eq!(validate_place(token).as_deref(), Ok(token));
        assert_eq!(
            validate_place("Lyon ⟦EMAIL_C697166FEEFB⟧").as_deref(),
            Ok("Lyon ⟦EMAIL_C697166FEEFB⟧")
        );
        // The token is percent-encoded like any non-letter; no value is added.
        let url = geocode_url("Lyon ⟦EMAIL_C697166FEEFB⟧");
        assert!(
            url.contains("%E2%9F%A6EMAIL_C697166FEEFB%E2%9F%A7"),
            "{url}"
        );
        // A malformed or unterminated delimiter is still refused.
        for bad in ["⟦PERSON 1⟧", "⟦PERSON_1", "⟦⟧", "⟦A@b⟧"] {
            assert!(validate_place(bad).is_err(), "{bad:?}");
        }
    }
}
