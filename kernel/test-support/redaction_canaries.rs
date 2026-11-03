// Invented secret-shaped inputs shared by the production redactor tests.
// These values are test data only; none are real credentials.

pub struct Canary {
    pub label: &'static str,
    pub input: &'static str,
    /// The secret spelling that must not remain, ignoring line breaks. This
    /// lets a case prove that a credential split across lines is removed.
    pub secret: &'static str,
}

pub const CANARIES: &[Canary] = &[
    Canary {
        label: "OpenAI-style key",
        input: "provider returned sk-auxesisCanary0123456789abcdef",
        secret: "sk-auxesisCanary0123456789abcdef",
    },
    Canary {
        label: "GitHub token in JSON",
        input: r#"{"token":"ghp_auxesisCanary0123456789abcdef"}"#,
        secret: "ghp_auxesisCanary0123456789abcdef",
    },
    Canary {
        label: "Slack bot token in quotes",
        input: "token='xoxb-auxesis-canary-0123456789'",
        secret: "xoxb-auxesis-canary-0123456789",
    },
    Canary {
        label: "Google API key",
        input: "AIzaSyAuxesisCanary0123456789",
        secret: "AIzaSyAuxesisCanary0123456789",
    },
    Canary {
        label: "Bearer JWT",
        input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.auxesisPayload012345.signature0123456789",
        secret: "eyJhbGciOiJIUzI1NiJ9.auxesisPayload012345.signature0123456789",
    },
    Canary {
        label: "JWT split at a newline",
        input: "BEARER eyJhbGciOiJIUzI1NiJ9.auxesisPayload012345\n.signature0123456789",
        secret: "eyJhbGciOiJIUzI1NiJ9.auxesisPayload012345.signature0123456789",
    },
    Canary {
        label: "32-character hex API key",
        input: "api_key=0123456789abcdef0123456789abcdef",
        secret: "0123456789abcdef0123456789abcdef",
    },
    Canary {
        label: "64-character hex API key",
        input: "API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    Canary {
        label: "URL user password",
        input: "https://buildbot:PassCanary_012345@service.example.invalid/v1",
        secret: "PassCanary_012345",
    },
    Canary {
        label: "uppercase Authorization header",
        input: "AUTHORIZATION: BEARER UpperCanary0123456789",
        secret: "UpperCanary0123456789",
    },
    Canary {
        label: "uppercase JSON key split at a newline",
        input: "{\"API_KEY\":\n  \"0123456789abcdef0123456789abcdef\"}",
        secret: "0123456789abcdef0123456789abcdef",
    },
];

pub fn assert_no_canaries(mut redact: impl FnMut(&str) -> String) {
    for canary in CANARIES {
        let output = redact(canary.input);
        let without_line_breaks = output.replace(['\n', '\r'], "");
        assert!(
            !without_line_breaks.contains(canary.secret),
            "{} survived redaction: {:?}",
            canary.label,
            output,
        );
    }
}
