//! The user-visible notification payload.

use kernel_broker::sanitize_text;

/// A notification to show to the user.
///
/// Title and body are *untrusted*: they can come from model output, job
/// summaries or provider errors. Transports sanitize them before rendering
/// (see [`Notification::sanitized`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Short headline (e.g. `"Auxesis"` or `"Job failed"`).
    pub title: String,
    /// Main text. May contain `\n` for multi-line notifications.
    pub body: String,
}

impl Notification {
    /// Build a notification from anything string-like.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
        }
    }

    /// A copy with control and invisible characters stripped by
    /// [`kernel_broker::sanitize_text`], keeping `\n` and `\t`.
    ///
    /// Notifiers render this form: invisible Unicode (ANSI escapes, bidi
    /// overrides, zero-width joiners, noncharacters) must never reach a
    /// notification the user might trust.
    pub fn sanitized(&self) -> Self {
        Self {
            title: sanitize_text(&self.title),
            body: sanitize_text(&self.body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_strips_control_and_invisible_characters() {
        let raw = Notification::new(
            "ti\u{1b}[31mtle\u{0}",
            "bo\u{0}dy\u{202e}\u{200b} with\nlines\tand\\quotes\"",
        );
        let clean = raw.sanitized();
        assert_eq!(clean.title, "ti[31mtle");
        assert_eq!(clean.body, "body with\nlines\tand\\quotes\"");
    }

    #[test]
    fn sanitized_keeps_plain_text_untouched() {
        let raw = Notification::new("Build done", "all 12 tests passed");
        assert_eq!(raw.sanitized(), raw);
    }
}
