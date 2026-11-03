//! Test-only canary corpus (DAEMON-HARDEN-1 fix r2).
//!
//! Every surface test drives these values through its display function, so a
//! surface cannot regress to a private scrubber. The vendor-shaped entries are
//! assembled at runtime (`format!`) so the tracked tree never contains a
//! literal that the repo secret scanner would have to allowlist; the values
//! are synthetic canaries either way.

/// `(raw text, secret that must not survive any display scrub)`.
pub(crate) fn canaries() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: String, secret: &str| cases.push((raw, secret.to_string()));

    // --- round 1: assignments, prefixes, PEM, JWT, env ---
    add("DB_PASSWORD=CANARYSECRET123".into(), "CANARYSECRET123");
    add(
        "MY_SERVICE_PASSWORD=CANARYSECRET123".into(),
        "CANARYSECRET123",
    );
    add(
        "GITHUB_CANCELLATION_TOKEN=x\ntoken=CANARYSECRET123".into(),
        "CANARYSECRET123",
    );
    add(
        "notatoken=1 then token=CANARYSECRET123".into(),
        "CANARYSECRET123",
    );
    add(
        "x-token=old and token=CANARYSECRET123".into(),
        "CANARYSECRET123",
    );
    add(
        "api_key=<redacted> markerapi_key allowed — api_key=CANARYSHOP8 markerapi_key".into(),
        "CANARYSHOP8",
    );
    add(
        format!("AKIA{}", "CANARYSHOP4AAA111BBB"),
        "CANARYSHOP4AAA111BBB",
    );
    add(
        format!("ghp_{}", "CANARYSHOP3aaa111bbb"),
        "CANARYSHOP3aaa111bbb",
    );
    add(format!("sk-{}", "canary-SHOP1aaa111"), "canary-SHOP1aaa111");
    add(format!("xoxb-{}", "1111-2222-CANARYSHOP5"), "CANARYSHOP5");
    add("api_key=CANARYSHOP8".into(), "CANARYSHOP8");
    add("password=CANARYSHOP9".into(), "CANARYSHOP9");
    add(
        format!(
            "eyJhbGciOiJIUzI1NiJ9.{}.sig{}",
            "eyJzdWIiOiJDQU5BUlkifQ", "CANARYSHOP6"
        ),
        "CANARYSHOP6",
    );
    add(
        "export AUX_KEY_DEEPSEEK = AUXCANARYSPACED42".into(),
        "AUXCANARYSPACED42",
    );
    add(
        "export AUX_KEY_DEEPSEEK\t=\tAUXCANARYTABBED43".into(),
        "AUXCANARYTABBED43",
    );
    add("ANTHROPIC_API_KEY=CANARYSHOP11".into(), "CANARYSHOP11");
    add(
        "AWS_SECRET_ACCESS_KEY=CANARYawssecret51".into(), // gitleaks:allow
        "CANARYawssecret51",
    );
    add("GITHUB_TOKEN=CANARYghenv54".into(), "CANARYghenv54"); // gitleaks:allow
    add("accessToken=CANARYE2ECAMEL18".into(), "CANARYE2ECAMEL18");
    add("dbPassword=CANARYE2ECAMEL19".into(), "CANARYE2ECAMEL19");
    add(
        "secretAccessKey=CANARYE2ECAMEL20".into(),
        "CANARYE2ECAMEL20",
    );
    add(
        "client_secret=CANARYclientsecret50".into(),
        "CANARYclientsecret50",
    );
    add("secret=CANARYsecretword52".into(), "CANARYsecretword52");

    // --- B2-01: colon/`:=`/JSON/YAML/ini spellings ---
    add(
        "{\"api_key\":\"CANARYJSONKEY0001\"}".into(),
        "CANARYJSONKEY0001",
    );
    add(
        "{\"password\":\"CANARYE2EJSON02\"}".into(),
        "CANARYE2EJSON02",
    );
    add("{\"token\":\"CANARYE2EJSON03\"}".into(), "CANARYE2EJSON03");
    add(
        "{\"client_secret\":\"CANARYE2EJSON04\"}".into(),
        "CANARYE2EJSON04",
    );
    add(
        "{\"AUX_KEY_DEEPSEEK\":\"CANARYE2EENV10\"}".into(),
        "CANARYE2EENV10",
    );
    add("api_key: CANARYE2EYAML02".into(), "CANARYE2EYAML02");
    add("  password: CANARYE2EYAML05".into(), "CANARYE2EYAML05");
    add("password:CANARYE2ECOLON03".into(), "CANARYE2ECOLON03");
    add("[creds]\napi_key: CANARYE2EINI04".into(), "CANARYE2EINI04");
    add("TOKEN: CANARYE2EUPPER05".into(), "CANARYE2EUPPER05");
    add("token := CANARYE2EWALRUS06".into(), "CANARYE2EWALRUS06"); // gitleaks:allow
    add(format!("api_key%3D{}", "CANARYE2EPCT12"), "CANARYE2EPCT12");
    add(
        format!("{{\"api_key\":\"{}\"}} unknown", "CANARYE2EJSON01"),
        "CANARYE2EJSON01",
    );

    // --- B2-02: URL/URI userinfo + url/uri/webhook names ---
    add(
        "postgres://app:CANARYE2EURL04@db.internal:5432/prod".into(),
        "CANARYE2EURL04",
    );
    add(
        "mongodb+srv://u:CANARYE2EURL05@cluster0/db".into(),
        "CANARYE2EURL05",
    );
    add(
        "redis://:CANARYE2EURL06@cache:6379/0".into(),
        "CANARYE2EURL06",
    );
    add(
        "amqp://guest:CANARYE2EURL07@mq:5672/%2f".into(),
        "CANARYE2EURL07",
    );
    add(
        "https://svc:CANARYE2EURL08@internal.example/db".into(),
        "CANARYE2EURL08",
    );
    add(
        "proxy=https://user:CANARYE2EURL09@proxy:3128".into(),
        "CANARYE2EURL09",
    );
    add(
        "DATABASE_URL=postgres://u:CANARYE2EURL10@h/d".into(),
        "CANARYE2EURL10",
    );
    add(
        format!(
            "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/{}/B00/xx",
            "CANARYHOOK0004"
        ),
        "CANARYHOOK0004",
    );

    // --- B2-03: credential headers ---
    add(
        "X-Api-Key: CANARYE2EHDR06ABCDEFGHIJ".into(), // gitleaks:allow
        "CANARYE2EHDR06ABCDEFGHIJ",
    );
    add(
        "X-Auth-Token: CANARYE2EHDR07ABCDEFGHIJ".into(), // gitleaks:allow
        "CANARYE2EHDR07ABCDEFGHIJ",
    );
    add(
        "Proxy-Authorization: Basic Q0FOQVNZVlJFTEIzNDU2Nzg5".into(),
        "Q0FOQVNZVlJFTEIzNDU2Nzg5",
    );
    add(
        "Cookie: session=CANARYE2ECOOKIE07abcdefghij".into(),
        "CANARYE2ECOOKIE07abcdefghij",
    );
    add(
        "X-Hub-Signature-256: sha256=CANARYE2EHDR08abcdef".into(),
        "CANARYE2EHDR08abcdef",
    );

    // --- B2-05: passphrase / credential(s) ---
    add("GPG_PASSPHRASE=CANARYE2EPASS08".into(), "CANARYE2EPASS08");
    add("SSH_PASSPHRASE=CANARYE2EPASS09".into(), "CANARYE2EPASS09");
    add("AWS_CREDENTIALS=CANARYE2ECRED10".into(), "CANARYE2ECRED10");
    add("DB_CREDENTIAL=CANARYE2ECRED11".into(), "CANARYE2ECRED11");

    // --- B2-06: PEM labels + PuTTY ---
    add(
        format!(
            "-----BEGIN private key-----\n{}\n-----END private key-----",
            "CANARYPEM0005abcdefgh"
        ),
        "CANARYPEM0005abcdefgh",
    );
    add(
        format!(
            "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 2\n{}\nPrivate-MAC: deadbeef",
            "CANARYPUTTY0004abcdefgh"
        ),
        "CANARYPUTTY0004abcdefgh",
    );

    // --- B2-09/B2-11: shape bands and error-body URL credentials ---
    add("Bearer abcdefghijklmnopqrst".into(), "abcdefghijklmnopqrst");
    add(
        "Authorization: 0123456789abcdef0123456789abcdef".into(),
        "0123456789abcdef0123456789abcdef",
    );
    add("http://CANARYE2EERR13@[".into(), "CANARYE2EERR13");
    add(
        format!("curl -u user:{} https://example.com", "CANARYE2ECURL16"), // gitleaks:allow
        "CANARYE2ECURL16",
    );

    cases
}

/// `(text, substring that must survive byte for byte)`.
pub(crate) fn false_positives() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: &str, keep: &str| cases.push((raw.to_string(), keep.to_string()));

    add("disk-usage is high", "disk-usage");
    add("The Bearer bonds are up", "Bearer bonds");
    add("Tokenization of the input", "Tokenization");
    add("AKIA is just a prefix", "AKIA is just a prefix");
    add(
        "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----",
        "MIICcanaryCERT",
    );
    add("check_id=1234 and password=short", "password=short");
    add("api_key= query parameter", "api_key= query parameter");
    add("token = ", "token =");
    add("eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9");
    add(
        "authorization is required for this route",
        "authorization is required",
    );
    add("I withdrew 100 USD from the bank", "I withdrew 100 USD");
    add("task-sk-1234", "task-sk-1234");
    add("disk-sk-usage", "disk-sk-usage");
    add("risk-sk-1", "risk-sk-1");
    add("public_key_sha256 = 9f2a1b3c", "9f2a1b3c");
    add("let token = parse(input);", "parse(input)");
    add("key = \"abcdefghijkl\"", "abcdefghijkl");
    add(
        "commit 9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
        "9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
    );
    add(
        "sha256=3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
        "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
    );
    add(
        "https://example.com/docs?page=2",
        "https://example.com/docs?page=2",
    );
    add("homepage_url=https://example.com", "https://example.com");
    add(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
        "iVBORw0KGgo",
    );
    add("{\"token\":\"abc\"}", "{\"token\":\"abc\"}");
    add("password: required", "password: required");
    add("token: None", "token: None");
    add(
        "fn check_key(token: &str) -> bool { token.len() > 0 }",
        "fn check_key(token: &str)",
    );
    add(
        "base_url = \"https://api.example.com/v1\"",
        "https://api.example.com/v1",
    );
    add("mailto:user@example.com", "mailto:user@example.com");
    add("https://example.com/a@b", "https://example.com/a@b");

    cases
}

/// Round-3 evasion canaries (78): the shapes security-review round 3 landed on six
/// client surfaces — pretty-printed and escaped JSON, invisible-character and
/// fullwidth obfuscation, bare cookie jars, percent-encoded DSNs and the
/// daemon log's own spellings.
///
/// Values are synthetic and assembled at runtime where a vendor prefix could
/// look like a committed credential.
pub(crate) fn round_3_canaries() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: String, secret: &str| cases.push((raw, secret.to_string()));

    // --- B3-01: a value on the line after its key/separator (14) ---
    add(
        "{\n  \"api_key\":\n    \"CANARY_E3E_MULTI01\"\n}".into(),
        "CANARY_E3E_MULTI01",
    );
    add(
        "{\n  \"password\":\n    \"CANARY_E3E_MULTI02\"\n}".into(),
        "CANARY_E3E_MULTI02",
    );
    add(
        "{\n  \"token\":\n    \"CANARY_E3E_MULTI03\"\n}".into(),
        "CANARY_E3E_MULTI03",
    );
    add(
        "api_key:\n  CANARY_E3E_MULTI04".into(),
        "CANARY_E3E_MULTI04",
    );
    add(
        "api_key:\r\n  CANARY_E3E_MULTI05".into(),
        "CANARY_E3E_MULTI05",
    );
    add(
        "payload: {\n  \"api_key\":\n    \"CANARY_E3E_MULTI06\"\n}".into(),
        "CANARY_E3E_MULTI06",
    );
    add(
        "export API_KEY=\\\nCANARY_E3E_MULTI07".into(),
        "CANARY_E3E_MULTI07",
    );
    add(
        "{\n  \"client_secret\":\n    \"CANARY_E3E_MULTI08\"\n}".into(),
        "CANARY_E3E_MULTI08",
    );
    add(
        "password:\n\tCANARY_E3E_MULTI09".into(),
        "CANARY_E3E_MULTI09",
    );
    add(
        "{\"a\":1,\n \"api_key\":\n \"CANARY_E3E_MULTI10\"}".into(),
        "CANARY_E3E_MULTI10",
    );
    add(
        "{\n  \"api_key\"\n  :\n  \"CANARY_E3E_MULTI11\"\n}".into(),
        "CANARY_E3E_MULTI11",
    );
    add(
        "token :=\n  CANARY_E3E_MULTI12".into(),
        "CANARY_E3E_MULTI12",
    );
    add(
        "password: \"hidden\nCANARY_E3E_MULTI13\"".into(),
        "CANARY_E3E_MULTI13",
    );
    add(
        "{\n  \"secretAccessKey\":\n  \"CANARY_E3E_MULTI14\"\n}".into(),
        "CANARY_E3E_MULTI14",
    );

    // --- B3-02: escaped quotes, nesting, JSON inside JSON (12) ---
    add(
        "{\"detail\":\"{\\\"api_key\\\":\\\"CANARYJSONKEY0001\\\"}\"}".into(),
        "CANARYJSONKEY0001",
    );
    add(
        "{\"password\":\"a\\\"b CANARY_E3E_ESCQ02\"}".into(),
        "CANARY_E3E_ESCQ02",
    );
    add(
        "{\"detail\":\"{\\\"password\\\":\\\"CANARY_E3E_ESCQ03\\\"}\",\"agent\":\"main\"}".into(),
        "CANARY_E3E_ESCQ03",
    );
    add(
        "api_key: \"{\\\"token\\\":\\\"CANARY_E3E_ESCQ04\\\"}\"".into(),
        "CANARY_E3E_ESCQ04",
    );
    add(
        "{\\\"api_key\\\":\\\"CANARY_E3E_ESCQ05\\\"}".into(),
        "CANARY_E3E_ESCQ05",
    );
    add(
        "\\\"api_key\\\":\\\"CANARY_E3E_ESCQ06\\\"".into(),
        "CANARY_E3E_ESCQ06",
    );
    add(
        "{\"outer\":{\"api_key\":\"CANARY_E3E_NEST07\"}}".into(),
        "CANARY_E3E_NEST07",
    );
    add(
        "{\"items\":[{\"token\":\"CANARY_E3E_NEST08\"}]}".into(),
        "CANARY_E3E_NEST08",
    );
    add(
        "{\"items\":[{\"api_key\":\"CANARY_E3E_NEST09\"},{\"password\":\"CANARY_E3E_NEST10\"}]}"
            .into(),
        "CANARY_E3E_NEST09",
    );
    add(
        "{\"detail\":{\"nested\":{\"client_secret\":\"CANARY_E3E_NEST11\"}}}".into(),
        "CANARY_E3E_NEST11",
    );
    add(
        "{\"a\":\"b\\\\\\\"c\",\"api_key\":\"CANARY_E3E_NEST12\"}".into(),
        "CANARY_E3E_NEST12",
    );
    add(
        "{\"detail\":\"[{\\\"token\\\":\\\"CANARY_E3E_NEST13\\\"}]\"}".into(),
        "CANARY_E3E_NEST13",
    );

    // --- B3-03: invisible/format characters (12) ---
    add("token\u{200b}=CANARY_E3E_LOG01".into(), "CANARY_E3E_LOG01");
    add(
        "api_\u{200b}key=CANARY_E3E_LOG02".into(), // gitleaks:allow
        "CANARY_E3E_LOG02",
    );
    add(
        "api_\u{00ad}key=CANARY_E3E_LOG03".into(),
        "CANARY_E3E_LOG03",
    );
    add(
        "api_key\u{00a0}=CANARY_E3E_LOG04".into(),
        "CANARY_E3E_LOG04",
    );
    add(
        format!("s\u{200b}k-{}", "CANARY_E3E_LOG05abcdefg"),
        "CANARY_E3E_LOG05",
    );
    add(
        format!("ghp\u{200b}_{}", "CANARY_E3E_LOG06abcdef"),
        "CANARY_E3E_LOG06",
    );
    add(
        "api_key\u{1b}[0m=CANARY_E3E_LOG07".into(),
        "CANARY_E3E_LOG07",
    );
    add("token=\u{202e}CANARY_E3E_LOG08".into(), "CANARY_E3E_LOG08");
    add("token=\u{feff}CANARY_E3E_LOG09".into(), "CANARY_E3E_LOG09");
    add("token=\u{2060}CANARY_E3E_LOG10".into(), "CANARY_E3E_LOG10");
    add("token\u{200d}=CANARY_E3E_LOG11".into(), "CANARY_E3E_LOG11");
    add("token\u{200e}=CANARY_E3E_LOG12".into(), "CANARY_E3E_LOG12");

    // --- B3-04: fullwidth separators (6) ---
    add("api_key＝CANARY_E3E_UNI01".into(), "CANARY_E3E_UNI01");
    add("api_key：CANARY_E3E_UNI02".into(), "CANARY_E3E_UNI02");
    add("token＝CANARY_E3E_UNI03".into(), "CANARY_E3E_UNI03");
    add("password：CANARY_E3E_UNI04".into(), "CANARY_E3E_UNI04");
    add(
        "{\"api_key\"：\"CANARY_E3E_UNI05\"}".into(),
        "CANARY_E3E_UNI05",
    );
    add(
        "api_key＝\u{3000}CANARY_E3E_UNI06".into(),
        "CANARY_E3E_UNI06",
    );

    // --- B3-05: bare cookie jars (10) ---
    add(
        "session=CANARY_E3E_COOKIE01abcdefghij; Path=/; HttpOnly".into(),
        "CANARY_E3E_COOKIE01",
    );
    add(
        "sid=CANARY_E3E_COOKIE02abcdefghijklmno".into(),
        "CANARY_E3E_COOKIE02",
    );
    add(
        "JSESSIONID=CANARY_E3E_COOKIE03abcdefghij".into(),
        "CANARY_E3E_COOKIE03",
    );
    add(
        "csrftoken=CANARY_E3E_COOKIE04abcdef".into(),
        "CANARY_E3E_COOKIE04",
    );
    add(
        "Cookie: a=1; session=CANARY_E3E_COOKIE05abcdefghij; Path=/".into(),
        "CANARY_E3E_COOKIE05",
    );
    add(
        "Set-Cookie: sid=CANARY_E3E_COOKIE06abcdefgh; HttpOnly".into(),
        "CANARY_E3E_COOKIE06",
    );
    add(
        "sessionid=CANARY_E3E_COOKIE07abcdefghij".into(),
        "CANARY_E3E_COOKIE07",
    );
    add(
        "csrf=CANARY_E3E_COOKIE08abcdefgh".into(),
        "CANARY_E3E_COOKIE08",
    );
    add(
        "SESSION=CANARY_E3E_COOKIE09abcdefghij".into(),
        "CANARY_E3E_COOKIE09",
    );
    add(
        "_session=CANARY_E3E_COOKIE10abcdefghij".into(),
        "CANARY_E3E_COOKIE10",
    );

    // --- B3-06: percent-encoded URLs (6) ---
    add(
        "postgres%3A%2F%2Fu:CANARY_E3E_URL01@h/d".into(),
        "CANARY_E3E_URL01",
    );
    add(
        "DATABASE_URL=postgres%3A%2F%2Fu:CANARY_E3E_URL02@h/d".into(),
        "CANARY_E3E_URL02",
    );
    add(
        "postgres%3a%2f%2fu:CANARY_E3E_URL03@h/d".into(),
        "CANARY_E3E_URL03",
    );
    add(
        "redis%3A%2F%2F:CANARY_E3E_URL04@cache:6379/0".into(),
        "CANARY_E3E_URL04",
    );
    add(
        "https%3A%2F%2Fuser:CANARY_E3E_URL05@example.com/x".into(),
        "CANARY_E3E_URL05",
    );
    add("api_key%3ACANARY_E3E_URL06".into(), "CANARY_E3E_URL06");

    // --- the shapes that kept working, pinned against the redesign (18) ---
    add(
        "token=7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8".into(), // gitleaks:allow
        "7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8",
    );
    add("password=CANARY_E3E_PASS01".into(), "CANARY_E3E_PASS01");
    add(
        "client_secret=CANARY_E3E_CLIENT02".into(),
        "CANARY_E3E_CLIENT02",
    );
    add(
        "DB_CREDENTIAL=CANARY_E3E_CRED03".into(),
        "CANARY_E3E_CRED03",
    );
    add(
        "AUX_KEY_ANTHROPIC=CANARY_E3E_ENV04".into(),
        "CANARY_E3E_ENV04",
    );
    add("GPG_PASSPHRASE=CANARY_E3E_GPG05".into(), "CANARY_E3E_GPG05");
    add(
        "X-Api-Key: CANARY_E3E_HDR06ABCDEF".into(), // gitleaks:allow
        "CANARY_E3E_HDR06ABCDEF",
    );
    add("Cookie: sid=CANARY_E3E_HDR07".into(), "CANARY_E3E_HDR07");
    add("Set-Cookie: id=CANARY_E3E_HDR08".into(), "CANARY_E3E_HDR08");
    add(
        "Authorization: Bearer CANARY_E3E_HDR09abcdefgh".into(),
        "CANARY_E3E_HDR09abcdefgh",
    );
    add(
        "password=Q0FOQVNZVlJFQllLRVhUUkVQ".into(), // gitleaks:allow
        "Q0FOQVNZVlJFQllLRVhUUkVQ",
    );
    add(
        "secret=0f1e2d3c4b5a69788796a5b4c3d2e1f0".into(), // gitleaks:allow
        "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    );
    add(
        "token: \"CANARY_E3E_QUOTED10\"".into(),
        "CANARY_E3E_QUOTED10",
    );
    add(
        "api_key=\n  CANARY_E3E_MULTI15".into(),
        "CANARY_E3E_MULTI15",
    );
    add(
        "{\"key\":\"CANARY_E3E_WEAK16\"}".into(),
        "CANARY_E3E_WEAK16",
    );
    add(
        "{ \"db_password\" : \"CANARY_E3E_SPACED17\" }".into(),
        "CANARY_E3E_SPACED17",
    );
    add("api_key:\nCANARY_E3E_MULTI18".into(), "CANARY_E3E_MULTI18");
    add(
        "password = \"two words CANARY_E3E_QUOTED19\"".into(),
        "CANARY_E3E_QUOTED19",
    );

    cases
}

/// Round-3 false positives (51): strings the redesign must keep, especially
/// identifiers, epochs, hashes, credential-free URLs and the ordinary prose
/// the tokenizer crosses.
pub(crate) fn round_3_false_positives() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: &str, keep: &str| cases.push((raw.to_string(), keep.to_string()));
    const UUID: &str = "7f2c1b3a-4d5e-6f70-8192-a3b4c5d6e7f8";
    const SHA: &str = "9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90";

    add(&format!("token_id: {UUID}"), UUID);
    add("token: 1699999999999", "1699999999999");
    add("password: MySecretValue123", "MySecretValue123");
    add(&format!("session_id={UUID}"), UUID);
    add(&format!("uuid={UUID}"), UUID);
    add(&format!("key_id={UUID}"), UUID);
    add("request_id=1699999999999-abc", "1699999999999-abc");
    add(&format!("commit {SHA}"), SHA);
    add(&format!("build_sha={SHA}"), SHA);
    add(
        "public_key_sha256=3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
        "3f786850e387550fdab836ed7e6dc881de23001bcc8f7d4b2c9b3c8d3e8f1a2b3",
    );
    add(
        "sha1=2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    );
    add(
        "md5=9e107d9d372bb6826bd81d3542a419d6",
        "9e107d9d372bb6826bd81d3542a419d6",
    );
    add("checksum=3f786850e387550f", "3f786850e387550f");
    add("hash=9f2a1b3c", "hash=9f2a1b3c");
    add("version: 1.2.3", "version: 1.2.3");
    add("at 12:30:45 the job ran", "12:30:45");
    add("the epoch 1699999999999 is a timestamp", "1699999999999");
    add(
        "token buckets refill at 10 per second",
        "token buckets refill",
    );
    add("password policy requires 12 characters", "12 characters");
    add("session management is enabled", "session management");
    add("a session cookie is not a secret here", "session cookie");
    add("the sid variable is set", "sid variable");
    add("sid=abc", "sid=abc");
    add("api_key= query parameter", "api_key= query parameter");
    add("api_key: query parameter", "api_key: query parameter");
    add("passphrase: optional", "passphrase: optional");
    add("password: required", "password: required");
    add("token: None", "token: None");
    add("password: Option<String>", "Option<String>");
    add("token: String", "token: String");
    add("let token = parse(input);", "parse(input)");
    add(
        "fn check_key(token: &str) -> bool { token.len() > 0 }",
        "check_key(token: &str)",
    );
    add("key = \"abcdefghijkl\"", "abcdefghijkl");
    add(
        "base_url = \"https://api.example.com/v1\"",
        "https://api.example.com/v1",
    );
    add("homepage_url=https://example.com", "https://example.com");
    add(
        "https://example.com/docs?page=2",
        "https://example.com/docs?page=2",
    );
    add(
        "postgres%3A%2F%2Fexample%2Ecom/db",
        "postgres%3A%2F%2Fexample%2Ecom/db",
    );
    add(
        "DATABASE_URL=postgres%3A%2F%2Fexample%2Ecom/db",
        "postgres%3A%2F%2Fexample%2Ecom/db",
    );
    add(
        "redis%3A%2F%2Flocalhost%3A6379/0",
        "redis%3A%2F%2Flocalhost%3A6379/0",
    );
    add("mailto:user@example.com", "mailto:user@example.com");
    add("https://example.com/a@b", "https://example.com/a@b");
    add(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
        "iVBORw0KGgo",
    );
    add(
        "-----BEGIN CERTIFICATE-----\nMIICcanaryCERT\n-----END CERTIFICATE-----",
        "MIICcanaryCERT",
    );
    add(
        "Content-Security-Policy: default-src 'self'",
        "Content-Security-Policy",
    );
    add("Secret Santa gift exchange", "Secret Santa");
    add("disk-usage is high", "disk-usage");
    add("task-sk-1234", "task-sk-1234");
    add("disk-sk-usage", "disk-sk-usage");
    add("The Bearer bonds are up", "Bearer bonds");
    add("bearer of bad news", "bearer of bad news");
    add("basic arithmetic is easy", "basic arithmetic");

    cases
}

/// The round-5 shapes: bracketed values, padded JSON keys, folded
/// `Bearer`/`Basic` values and sibling name/value pairs
/// (B5-01/B5-02/B5-04/E5-01).
pub(crate) fn round_5_canaries() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: String, secret: &str| cases.push((raw, secret.to_string()));

    add(
        format!("api_key=({})", "CANARY_B5_01_PAREN01"),
        "CANARY_B5_01_PAREN01",
    );
    add(
        format!("password=({})", "CANARY_B5_01_PASSW02"),
        "CANARY_B5_01_PASSW02",
    );
    add(
        format!("api_key=<{}>", "CANARY_B5_01_ANGLE3"),
        "CANARY_B5_01_ANGLE3",
    );
    add(
        format!("{{ \" api_key \" : \"{}\" }}", "CANARY_B5_02_PADDED4"),
        "CANARY_B5_02_PADDED4",
    );
    add(
        format!("{{ \"api_key \" : \"{}\"}}", "CANARY_B5_02_PADDED5"),
        "CANARY_B5_02_PADDED5",
    );
    add(
        format!("Bearer\n {}", "CANARY_B5_04_FOLDED06"),
        "CANARY_B5_04_FOLDED06",
    );
    add(
        format!("Basic\n {}", "YWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        "YWxhZGRpbjpvcGVuIHNlc2FtZQ",
    );
    add(
        format!(
            "{{\"name\":\"api_key\",\"value\":\"{}\"}}",
            "CANARY_E5_01_NAME07"
        ),
        "CANARY_E5_01_NAME07",
    );
    add(
        format!(
            "{{\"key\":\"api_key\",\"value\":\"{}\"}}",
            "CANARY_E5_01_KEY08"
        ),
        "CANARY_E5_01_KEY08",
    );
    add(
        format!(
            "{{\"field\":\"password\",\"content\":\"{}\"}}",
            "CANARY_E5_01_FIELD9"
        ),
        "CANARY_E5_01_FIELD9",
    );
    add(
        format!(
            "{{\"arguments\":{{\"name\":\"api_key\",\"value\":\"{}\"}}}}",
            "CANARY_E5_01_ARG10"
        ),
        "CANARY_E5_01_ARG10",
    );
    add(
        format!("[\"api_key\",\"{}\"]", "CANARY_E5_01_ARRAY1"),
        "CANARY_E5_01_ARRAY1",
    );
    add(
        format!(
            "{{\"variable\":\"DB_PASSWORD\",\"val\":\"{}\"}}",
            "CANARY_E5_01_VAR12"
        ),
        "CANARY_E5_01_VAR12",
    );
    add(
        format!("[\"Authorization\",\"Bearer {}\"]", "CANARY_E5_01_AUTH13"),
        "CANARY_E5_01_AUTH13",
    );

    cases
}

/// Prose the round-5 normalise fix must not touch (H-05/B5-07).
pub(crate) fn round_5_false_positives() -> Vec<(String, String)> {
    let mut cases: Vec<(String, String)> = Vec::new();
    let mut add = |raw: &str, keep: &str| cases.push((raw.to_string(), keep.to_string()));

    add("He said “hello” and don’t stop — really…", "“hello”");
    add("简体中文、，。！？；：（）《》", "简体中文、");
    add("全角記号：ＡＢＣ－ＸＹＺ，！？", "ＡＢＣ－ＸＹＺ");
    add("価格：100円！重要", "100円！");
    add("ok 👍 done 🎉 shipped 🚀", "🎉 shipped");
    add("price＝100", "price＝100");
    add("price：100", "price：100");
    add("password=(short)", "password=(short)");
    add("the (secret) ingredient", "the (secret) ingredient");
    add(r#"{"name":"agent-name","value":"main"}"#, "agent-name");
    add(r#"["key","value"]"#, r#"["key","value"]"#);

    cases
}

/// The base corpus plus every round-3 canary, for the per-surface tables.
pub(crate) fn all_canaries() -> Vec<(String, String)> {
    let mut cases = canaries();
    cases.extend(round_3_canaries());
    cases.extend(round_5_canaries());
    cases
}

/// The base false-positive corpus plus every round-3 string.
pub(crate) fn all_false_positives() -> Vec<(String, String)> {
    let mut cases = false_positives();
    cases.extend(round_3_false_positives());
    cases.extend(round_5_false_positives());
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_3_tables_hold_the_78_and_51_contract() {
        let canaries = round_3_canaries();
        let fps = round_3_false_positives();
        assert_eq!(canaries.len(), 78, "round-3 canary count");
        assert_eq!(fps.len(), 51, "round-3 false-positive count");
        for (raw, secret) in &canaries {
            assert!(!raw.is_empty(), "empty canary for {secret}");
            assert!(!secret.is_empty(), "empty secret in {raw:?}");
        }
        for (raw, keep) in &fps {
            assert!(raw.contains(keep.as_str()), "{raw:?} lacks {keep:?}");
        }
    }

    #[test]
    fn round_5_tables_hold_their_contract() {
        let canaries = round_5_canaries();
        let fps = round_5_false_positives();
        assert_eq!(canaries.len(), 14, "round-5 canary count");
        assert_eq!(fps.len(), 11, "round-5 false-positive count");
        for (raw, secret) in &canaries {
            assert!(!raw.is_empty() && !secret.is_empty(), "empty entry {raw:?}");
        }
        for (raw, keep) in &fps {
            assert!(raw.contains(keep.as_str()), "{raw:?} lacks {keep:?}");
        }
    }
}
