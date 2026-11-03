#[derive(Clone, Copy, Default)]
enum Mode {
    #[default]
    Plain,
    Url,
    Markdown(usize),
    Angle(char),
    AngleProbe,
    Reference,
}

const MAX_ATTR_LOOKAHEAD: usize = 4_096;
const URL_ENTITIES: [(&[u8], char); 8] = [
    (b"colon", ':'),
    (b"sol", '/'),
    (b"period", '.'),
    (b"quest", '?'),
    (b"num", '#'),
    (b"amp", '&'),
    (b"commat", '@'),
    (b"equals", '='),
];

#[derive(Clone, Copy, Default)]
enum EntityStage {
    #[default]
    Text,
    Amp,
    Name,
    Hash,
    HexStart,
    Decimal,
    Hex,
}

#[derive(Clone, Default)]
struct HtmlEntityScan {
    stage: EntityStage,
    name: [u8; 6],
    name_len: usize,
    number: u32,
    digits: usize,
    overflow: bool,
}

impl HtmlEntityScan {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn name_prefix(&self) -> bool {
        let name = &self.name[..self.name_len];
        URL_ENTITIES
            .iter()
            .any(|(known, _)| known.starts_with(name))
    }

    fn name_value(&self) -> Option<char> {
        let name = &self.name[..self.name_len];
        URL_ENTITIES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, value)| *value)
    }

    fn digit(&mut self, value: u32, radix: u32) {
        self.digits += 1;
        if self.number > (u32::MAX - value) / radix {
            self.overflow = true;
        } else {
            self.number = self.number * radix + value;
        }
    }

    fn decoded_number(&self) -> char {
        if self.overflow {
            return '\u{fffd}';
        }
        char::from_u32(self.number)
            .filter(|ch| *ch != '\0')
            .unwrap_or('\u{fffd}')
    }
}

#[derive(Clone)]
struct UrlShapeScan {
    previous: char,
    scheme: u8,
    host: String,
    host_allowed: bool,
    found: bool,
    entity: HtmlEntityScan,
}

impl Default for UrlShapeScan {
    fn default() -> Self {
        Self {
            previous: '\0',
            scheme: 0,
            host: String::new(),
            host_allowed: true,
            found: false,
            entity: HtmlEntityScan::default(),
        }
    }
}

impl UrlShapeScan {
    fn reset(&mut self) {
        self.previous = '\0';
        self.scheme = 0;
        self.host.clear();
        self.host_allowed = true;
        self.found = false;
        self.entity.reset();
    }

    fn push(&mut self, ch: char) {
        if self.found {
            return;
        }
        let mut next = Some(ch);
        while let Some(ch) = next.take() {
            match self.entity.stage {
                EntityStage::Text if ch == '&' => self.entity.stage = EntityStage::Amp,
                EntityStage::Text => self.push_shape(ch),
                EntityStage::Amp if ch == '#' => self.entity.stage = EntityStage::Hash,
                EntityStage::Amp if ch.is_ascii_alphabetic() => {
                    self.entity.name[0] = ch.to_ascii_lowercase() as u8;
                    self.entity.name_len = 1;
                    self.entity.stage = EntityStage::Name;
                    if !self.entity.name_prefix() {
                        self.flush_entity();
                    }
                }
                EntityStage::Amp => {
                    self.flush_entity();
                    next = Some(ch);
                }
                EntityStage::Name if ch == ';' => {
                    if let Some(value) = self.entity.name_value() {
                        self.entity.reset();
                        self.push_shape(value);
                    } else {
                        self.flush_entity();
                        self.push_shape(';');
                    }
                }
                EntityStage::Name
                    if ch.is_ascii_alphabetic()
                        && self.entity.name_len < self.entity.name.len() =>
                {
                    self.entity.name[self.entity.name_len] = ch.to_ascii_lowercase() as u8;
                    self.entity.name_len += 1;
                    if !self.entity.name_prefix() {
                        self.flush_entity();
                    }
                }
                EntityStage::Name if ch.is_ascii_alphabetic() => {
                    self.flush_entity();
                    next = Some(ch);
                }
                EntityStage::Name => {
                    if !ch.is_ascii_alphanumeric() && ch != '=' {
                        if let Some(value) = self.entity.name_value() {
                            self.entity.reset();
                            self.push_shape(value);
                            next = Some(ch);
                            continue;
                        }
                    }
                    self.flush_entity();
                    next = Some(ch);
                }
                EntityStage::Hash if ch == 'x' || ch == 'X' => {
                    self.entity.stage = EntityStage::HexStart;
                }
                EntityStage::Hash if ch.is_ascii_digit() => {
                    self.entity.stage = EntityStage::Decimal;
                    self.entity.digit(ch.to_digit(10).unwrap_or(0), 10);
                }
                EntityStage::Hash => {
                    self.flush_entity();
                    next = Some(ch);
                }
                EntityStage::HexStart if ch.is_ascii_hexdigit() => {
                    self.entity.stage = EntityStage::Hex;
                    self.entity.digit(ch.to_digit(16).unwrap_or(0), 16);
                }
                EntityStage::Decimal if ch.is_ascii_digit() => {
                    self.entity.digit(ch.to_digit(10).unwrap_or(0), 10);
                }
                EntityStage::Hex if ch.is_ascii_hexdigit() => {
                    self.entity.digit(ch.to_digit(16).unwrap_or(0), 16);
                }
                EntityStage::Decimal | EntityStage::Hex if ch == ';' => {
                    let value = self.entity.decoded_number();
                    self.entity.reset();
                    self.push_shape(value);
                }
                EntityStage::Decimal | EntityStage::Hex => {
                    let value = self.entity.decoded_number();
                    self.entity.reset();
                    self.push_shape(value);
                    next = Some(ch);
                }
                EntityStage::HexStart => {
                    self.flush_entity();
                    next = Some(ch);
                }
            }
        }
    }

    fn flush_entity(&mut self) {
        let entity = std::mem::take(&mut self.entity);
        match entity.stage {
            EntityStage::Text => {}
            EntityStage::Amp => self.push_shape('&'),
            EntityStage::Name => {
                self.push_shape('&');
                for &ch in &entity.name[..entity.name_len] {
                    self.push_shape(ch as char);
                }
            }
            EntityStage::Hash => {
                self.push_shape('&');
                self.push_shape('#');
            }
            EntityStage::HexStart => {
                self.push_shape('&');
                self.push_shape('#');
                self.push_shape('x');
            }
            EntityStage::Decimal | EntityStage::Hex => {
                self.push_shape(entity.decoded_number());
            }
        }
    }

    fn push_shape(&mut self, ch: char) {
        if self.found {
            return;
        }
        if (self.previous == '/' && ch == '/') || matches!(ch, ':' | '\u{FF1A}') && self.scheme == 1
        {
            self.found = true;
            return;
        }
        self.scheme = match (self.scheme, ch) {
            (0, ch) if ch.is_ascii_alphabetic() => 1,
            (1, ch) if scheme_char(ch) => 1,
            (_, ch) if ch.is_ascii_alphabetic() => 1,
            _ => 0,
        };
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
            if self.host_allowed && self.host.len() < 255 {
                self.host.push(ch.to_ascii_lowercase());
            } else if self.host_allowed {
                self.host.clear();
            }
        } else {
            self.found = domain_name(&self.host);
            self.host.clear();
            self.host_allowed = ch.is_whitespace() || !matches!(ch, '@' | '_' | '.' | '-');
        }
        self.previous = ch;
    }

    fn finish(&mut self) -> bool {
        match self.entity.stage {
            EntityStage::Name if self.entity.name_value().is_some() => {
                let value = self.entity.name_value().unwrap_or('\0');
                self.entity.reset();
                self.push_shape(value);
            }
            EntityStage::Decimal | EntityStage::Hex => {
                let value = self.entity.decoded_number();
                self.entity.reset();
                self.push_shape(value);
            }
            _ => self.flush_entity(),
        }
        self.found || domain_name(&self.host)
    }
}

pub struct LinkGuard {
    mode: Mode,
    previous: char,
    www_stage: u8,
    scheme_stage: u8,
    scheme_len: usize,
    scheme_prefix: [u8; 7],
    angle_chars: usize,
    angle_tag: bool,
    pending_email: Option<String>,
    host: String,
    host_allowed: bool,
    angle_attr: String,
    angle_attr_space: bool,
    angle_link_attr: bool,
    angle_attr_value: bool,
    angle_value_started: bool,
    angle_value_scan: UrlShapeScan,
    line_start: bool,
    ref_stage: u8,
    ref_spaces: u8,
    redactions: usize,
    escape: bool,
}

impl Default for LinkGuard {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            previous: '\0',
            www_stage: 0,
            scheme_stage: 0,
            scheme_len: 0,
            scheme_prefix: [0; 7],
            angle_chars: 0,
            angle_tag: true,
            pending_email: None,
            host: String::new(),
            host_allowed: true,
            angle_attr: String::new(),
            angle_attr_space: false,
            angle_link_attr: false,
            angle_attr_value: false,
            angle_value_started: false,
            angle_value_scan: UrlShapeScan::default(),
            line_start: true,
            ref_stage: 0,
            ref_spaces: 0,
            redactions: 0,
            escape: false,
        }
    }
}

impl LinkGuard {
    pub fn is_link_target(&self) -> bool {
        (match self.mode {
            Mode::Plain | Mode::AngleProbe => false,
            Mode::Angle(_) => self.angle_link_attr,
            _ => true,
        }) || self.scheme_stage >= 2
    }
    pub fn append_to(&mut self, out: &mut String, text: &str) {
        for ch in text.chars() {
            if let Some(email) = self.pending_email.take() {
                if ch == '>' {
                    out.push('[');
                    out.push_str(&email);
                    out.push_str("](mailto:[hidden])");
                    self.redactions += 1;
                    self.previous = ch;
                    continue;
                }
                self.append_to(out, &format!("<{email}"));
            }
            out.push(ch);
            self.push_char(ch);
        }
    }
    pub fn append_value(&mut self, out: &mut String, value: &str) -> bool {
        self.flush_pending_email(out);
        self.append_value_kind(out, value, false)
    }
    pub fn append_token_value(
        &mut self,
        out: &mut String,
        token: &str,
        value: &str,
        after: &str,
        last: bool,
    ) -> Option<bool> {
        self.prepare_token_context(after, last)?;
        self.flush_pending_email(out);
        if matches!(self.mode, Mode::AngleProbe)
            && self.angle_chars == 0
            && token.starts_with("EMAIL_")
            && email_address(value)
        {
            // A closed e-mail autolink keeps its visible address in a Markdown
            // label while its fetchable mailto target remains hidden.
            out.pop();
            self.pending_email = Some(value.to_string());
            self.end_angle();
            return Some(true);
        }
        Some(self.append_value_kind(out, value, false))
    }
    /// Resolve a token only after enough input is available to tell whether it
    /// begins a bare-host label or an attribute value that later contains a URL.
    fn prepare_token_context(&mut self, after: &str, last: bool) -> Option<()> {
        if self.is_link_target() {
            return Some(());
        }
        if self.attribute_value_active() {
            return match self.attribute_link_ahead(after, last) {
                Some(true) => {
                    self.angle_link_attr = true;
                    Some(())
                }
                Some(false) => Some(()),
                None => None,
            };
        }
        if matches!(self.mode, Mode::Plain) {
            return match self.host_link_ahead(after, last) {
                Some(true) => {
                    self.mode = Mode::Url;
                    self.clear();
                    Some(())
                }
                Some(false) => Some(()),
                None => None,
            };
        }
        Some(())
    }
    fn append_value_kind(&mut self, out: &mut String, value: &str, _email: bool) -> bool {
        let hidden = self.is_link_target() || contains_link_target(value);
        if !hidden && value.contains(crate::PLACEHOLDER_OPEN) {
            return false;
        }
        if hidden {
            if self.attribute_value_active() {
                self.angle_link_attr = true;
            }
            self.redactions += 1;
            self.start_pending_url();
        }
        self.append_to(out, if hidden { "[hidden]" } else { value });
        true
    }
    fn attribute_value_active(&self) -> bool {
        self.angle_attr_value && matches!(self.mode, Mode::Angle(_))
    }
    fn attribute_link_ahead(&self, after: &str, last: bool) -> Option<bool> {
        if self.angle_link_attr || self.angle_value_scan.found {
            return Some(true);
        }
        let quote = match self.mode {
            Mode::Angle(quote) => quote,
            _ => return Some(false),
        };
        let mut scan = self.angle_value_scan.clone();
        let mut consumed = 0;
        for ch in after.chars() {
            if (quote != '\0' && ch == quote)
                || (quote == '\0' && (ch.is_whitespace() || ch == '>'))
            {
                return Some(scan.finish());
            }
            consumed += ch.len_utf8();
            scan.push(ch);
            if scan.found {
                return Some(true);
            }
            if consumed >= MAX_ATTR_LOOKAHEAD {
                // A very long, unfinished attribute is treated as link-bearing
                // rather than rescanning an unbounded suffix for every token.
                return Some(true);
            }
        }
        if last {
            Some(scan.finish())
        } else {
            None
        }
    }
    fn host_link_ahead(&self, after: &str, last: bool) -> Option<bool> {
        if !self.host_allowed {
            return Some(false);
        }
        let mut host = self.host.clone();
        host.push('x');
        for ch in after.chars() {
            if !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '-') {
                return Some(domain_name(&host));
            }
            host.push(ch.to_ascii_lowercase());
            if host.len() > 255 {
                return Some(false);
            }
        }
        if domain_name(&host) {
            Some(true)
        } else if last || host.len() >= 255 || host.contains("..") {
            Some(false)
        } else {
            None
        }
    }
    pub fn take_redactions(&mut self) -> usize {
        std::mem::take(&mut self.redactions)
    }
    pub fn finish(&mut self, _out: &mut String) {
        self.flush_pending_email(_out);
        if matches!(self.mode, Mode::AngleProbe) {
            self.end_angle();
        }
    }
    fn flush_pending_email(&mut self, out: &mut String) {
        if let Some(email) = self.pending_email.take() {
            self.append_to(out, &format!("<{email}"));
        }
    }
    fn start_pending_url(&mut self) {
        if matches!(self.mode, Mode::Plain) && self.scheme_stage >= 2 {
            self.mode = Mode::Url;
            self.clear();
        }
    }
    fn push_char(&mut self, ch: char) {
        match self.mode {
            Mode::Plain => self.push_plain(ch),
            Mode::Url if ch.is_whitespace() && ch != '\n' && ch != '\r' => self.end_link(ch),
            Mode::Url => self.previous = ch,
            Mode::Reference if ch.is_whitespace() => self.end_link(ch),
            Mode::Reference => self.previous = ch,
            Mode::AngleProbe if ch.is_whitespace() && self.angle_tag && self.angle_chars > 0 => {
                self.mode = Mode::Angle('\0');
                self.angle_attr.clear();
                self.angle_link_attr = false;
                self.previous = ch;
            }
            Mode::AngleProbe if ch.is_whitespace() || ch == '>' => {
                self.end_angle();
                self.previous = ch;
            }
            Mode::AngleProbe => {
                self.angle_chars += 1;
                self.angle_tag &= if self.angle_chars == 1 {
                    ch.is_ascii_alphabetic()
                } else {
                    ch.is_ascii_alphanumeric() || matches!(ch, '-' | ':' | '_')
                };
                if !is_format_char(ch) {
                    self.advance_scheme(ch);
                    if !matches!(self.mode, Mode::Url) {
                        if (self.previous == '/' && ch == '/')
                            || (matches!(ch, '/' | '?' | '#') && domain_name(&self.host))
                        {
                            self.mode = Mode::Url;
                            self.clear();
                        } else {
                            self.advance_host(ch);
                        }
                    }
                }
                self.previous = ch;
            }
            Mode::Markdown(depth) => {
                let escaped = self.escape;
                self.escape = ch == '\\' && !self.escape;
                if ch == ')' && depth == 1 && !escaped {
                    self.end_link(ch);
                } else {
                    self.mode = Mode::Markdown(if ch == '(' {
                        if escaped {
                            depth
                        } else {
                            depth.saturating_add(1)
                        }
                    } else if ch == ')' {
                        if escaped {
                            depth
                        } else {
                            depth - 1
                        }
                    } else {
                        depth
                    });
                    self.previous = ch;
                }
            }
            Mode::Angle(quote) => self.push_angle(ch, quote),
        }
    }
    fn push_plain(&mut self, ch: char) {
        if self.reference_target(ch) {
            self.mode = Mode::Reference;
            self.ref_stage = 0;
        } else if self.previous == ']' && ch == '(' {
            self.mode = Mode::Markdown(1);
            self.clear();
        } else if ch == '<' {
            self.mode = Mode::AngleProbe;
            self.clear();
            self.angle_chars = 0;
            self.angle_tag = true;
            self.host_allowed = true;
        } else if (self.previous == '/' && ch == '/')
            || (matches!(ch, '/' | '?' | '#') && domain_name(&self.host))
        {
            self.mode = Mode::Url;
            self.clear();
        } else {
            if !is_format_char(ch) {
                self.advance_scheme(ch);
                if self.advance_www(ch) {
                    self.mode = Mode::Url;
                    self.clear();
                }
                self.advance_host(ch);
            }
        }
        self.previous = ch;
    }
    fn push_angle(&mut self, ch: char, quote: char) {
        if quote != '\0' {
            if quote == ch {
                self.mode = Mode::Angle('\0');
                self.angle_link_attr = false;
                self.angle_attr_value = false;
                self.angle_value_started = false;
                self.angle_attr.clear();
                self.angle_value_scan.reset();
            } else {
                self.angle_value_scan.push(ch);
                self.angle_link_attr |= self.angle_value_scan.found;
                self.previous = ch;
            }
        } else if ch == '>' {
            self.end_link(ch);
        } else if ch == '"' || ch == '\'' {
            self.angle_attr_space = false;
            self.mode = Mode::Angle(ch);
            self.angle_value_started = true;
            self.angle_value_scan.reset();
        } else if ch == '=' && !self.angle_attr_value {
            // srcset carries several fetchable candidates; inline style can
            // contain CSS url(), image-set(), or equivalent fetch targets.
            self.angle_link_attr = matches!(
                self.angle_attr.as_str(),
                "href" | "src" | "srcset" | "style"
            );
            self.angle_attr.clear();
            self.angle_attr_value = true;
            self.angle_value_started = false;
            self.angle_attr_space = false;
            self.angle_value_scan.reset();
            self.previous = ch;
        } else if ch.is_whitespace() {
            if self.angle_attr_value {
                if self.angle_value_started {
                    self.angle_link_attr = false;
                    self.angle_attr_value = false;
                    self.angle_value_started = false;
                    self.angle_attr.clear();
                    self.angle_value_scan.reset();
                }
            } else {
                self.angle_link_attr = false;
                self.angle_attr_space = !self.angle_attr.is_empty();
                self.angle_value_scan.reset();
            }
            self.previous = ch;
        } else if self.angle_attr_value {
            self.angle_value_started = true;
            self.angle_value_scan.push(ch);
            self.angle_link_attr |= self.angle_value_scan.found;
            self.previous = ch;
        } else {
            if self.angle_attr_space {
                self.angle_attr.clear();
                self.angle_attr_space = false;
            }
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':') {
                self.angle_attr.push(ch.to_ascii_lowercase());
            } else {
                self.angle_attr.clear();
            }
            self.previous = ch;
        }
    }
    fn advance_scheme(&mut self, ch: char) {
        match self.scheme_stage {
            0 if ch.is_ascii_alphabetic() => {
                self.scheme_stage = 1;
                self.scheme_len = 1;
                self.scheme_prefix[0] = ch.to_ascii_lowercase() as u8;
            }
            1 if scheme_char(ch) => {
                self.scheme_len = self.scheme_len.saturating_add(1);
                if self.scheme_len <= self.scheme_prefix.len() {
                    self.scheme_prefix[self.scheme_len - 1] = ch.to_ascii_lowercase() as u8;
                }
            }
            1 if matches!(ch, ':' | '\u{FF1A}') => {
                let special = match self.scheme_len {
                    3 => &self.scheme_prefix[..3] == b"tel",
                    4 => &self.scheme_prefix[..4] == b"data",
                    6 => &self.scheme_prefix[..6] == b"mailto",
                    _ => false,
                };
                if special {
                    self.mode = Mode::Url;
                    self.clear();
                } else {
                    self.scheme_stage = 2;
                }
            }
            2 if ch == '/' => {
                self.mode = Mode::Url;
                self.clear();
            }
            2 if matches!(ch, '\n' | '\r') => {}
            3 if ch == '/' => {
                self.mode = Mode::Url;
                self.clear();
            }
            3 if matches!(ch, '\n' | '\r') => {}
            _ => {
                self.clear_scheme();
                if ch.is_ascii_alphabetic() {
                    self.scheme_stage = 1;
                    self.scheme_len = 1;
                    self.scheme_prefix[0] = ch.to_ascii_lowercase() as u8;
                }
            }
        }
    }
    fn advance_www(&mut self, ch: char) -> bool {
        let is_w = ch.eq_ignore_ascii_case(&'w');
        match self.www_stage {
            1 if is_w => self.www_stage = 2,
            2 if is_w => self.www_stage = 3,
            3 if ch == '.' => return true,
            _ => {
                self.www_stage =
                    u8::from(is_w && !self.previous.is_ascii_alphanumeric() && self.previous != '_')
            }
        }
        false
    }
    fn end_link(&mut self, ch: char) {
        self.mode = Mode::Plain;
        self.clear();
        self.previous = ch;
        self.host_allowed = ch.is_whitespace() || !matches!(ch, '@' | '_' | '.' | '-');
        self.line_start = matches!(ch, '\n' | '\r');
        self.ref_stage = 0;
        self.ref_spaces = 0;
    }
    fn end_angle(&mut self) {
        self.mode = Mode::Plain;
        self.clear();
        self.host_allowed = true;
    }
    fn clear(&mut self) {
        self.www_stage = 0;
        self.escape = false;
        self.host.clear();
        self.host_allowed = false;
        self.angle_attr.clear();
        self.angle_attr_space = false;
        self.angle_link_attr = false;
        self.angle_attr_value = false;
        self.angle_value_started = false;
        self.angle_value_scan.reset();
        self.ref_stage = 0;
        self.angle_chars = 0;
        self.angle_tag = true;
        self.clear_scheme();
    }
    fn clear_scheme(&mut self) {
        self.scheme_stage = 0;
        self.scheme_len = 0;
    }
    fn advance_host(&mut self, ch: char) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
            if self.host_allowed && self.host.len() < 255 {
                self.host.push(ch.to_ascii_lowercase());
            } else if self.host_allowed {
                self.host.clear();
            }
        } else {
            self.host.clear();
            self.host_allowed = ch.is_whitespace() || !matches!(ch, '@' | '_' | '.' | '-');
        }
    }
    fn reference_target(&mut self, ch: char) -> bool {
        if matches!(ch, '\n' | '\r') {
            self.line_start = true;
            self.ref_stage = 0;
            self.ref_spaces = 0;
            return false;
        }
        if self.ref_stage == 0 {
            if self.line_start && ch == ' ' && self.ref_spaces < 3 {
                self.ref_spaces += 1;
                return false;
            }
            if self.line_start && ch == '[' {
                self.line_start = false;
                self.ref_stage = 1;
                self.ref_spaces = 0;
                return false;
            }
            self.line_start = false;
            self.ref_spaces = 0;
            return false;
        }
        match self.ref_stage {
            1 if ch == ']' => self.ref_stage = 2,
            1 => {}
            2 if ch == ':' => self.ref_stage = 3,
            2 => self.ref_stage = 0,
            3 if ch.is_whitespace() => self.ref_stage = 4,
            3 => self.ref_stage = 0,
            4 if ch.is_whitespace() => return false,
            4 => return true,
            _ => self.ref_stage = 0,
        }
        false
    }
}
fn contains_link_target(text: &str) -> bool {
    let mut guard = LinkGuard::default();
    let mut angle_start = None;
    for (at, ch) in text.char_indices() {
        let closes_email = ch == '>'
            && matches!(guard.mode, Mode::AngleProbe)
            && angle_start
                .and_then(|start| text.get(start + 1..at))
                .is_some_and(email_address);
        // Validate a candidate only when a character can end it. Testing the
        // delimiter first avoids rescanning the current host for every prose
        // character (notably repeated `a.aa` candidates).
        if !ch.is_ascii_alphanumeric()
            && !matches!(ch, '@' | '_' | '.' | '-')
            && domain_name(&guard.host)
        {
            return true;
        }
        let angle_whitespace = matches!(guard.mode, Mode::AngleProbe) && ch.is_whitespace();
        guard.push_char(ch);
        if guard.is_link_target() || guard.scheme_stage >= 2 || closes_email {
            return true;
        }
        if angle_whitespace {
            angle_start = None;
        } else if ch == '<' {
            angle_start = Some(at);
        }
    }
    domain_name(&guard.host)
}
fn domain_name(text: &str) -> bool {
    let Some((_, last)) = text.rsplit_once('.') else {
        return false;
    };
    last.len() >= 2
        && last.chars().all(|ch| ch.is_ascii_alphabetic())
        && text.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
}
fn email_address(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~@".contains(ch))
}
fn is_format_char(ch: char) -> bool {
    matches!(ch as u32, 0x00AD | 0x034F | 0x061C | 0x180E | 0x200B..=0x200F
        | 0x202A..=0x202E | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x1BCA0..=0x1BCAF | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}
fn scheme_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')
}
