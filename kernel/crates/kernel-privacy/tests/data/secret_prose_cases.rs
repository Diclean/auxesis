// SECRET-PROSE cases, shared by `tests/secret_prose.rs`. Every value is invented and
// built at runtime: no key-shaped literal sits in a file.

/// The tail every invented key and cookie value is cut from.
pub const KEY_TAIL: &str = "q7Lm2Vt9Rw4Zp8Kx3Nb6Hy5Jc1";

/// An invented API key: a prefix and `n` chars of the tail.
pub fn key(prefix: &str, n: usize) -> String {
    format!("{prefix}{}", &KEY_TAIL[..n])
}

/// An invented password: a head and a tail picked by `i`.
pub fn pw(i: usize) -> String {
    const HEADS: [&str; 6] = ["Hv4", "Rk8", "Tm2", "Wq5", "Zb7", "Np3"];
    const TAILS: [&str; 6] = ["!pQz9L", "#yXc4e", "@uJk2s", "$wDf8n", "%oPl6r", "&iMv3t"];
    format!("{}{}", HEADS[i % 6], TAILS[(i / 6 + i) % 6])
}

/// An invented word password, such as a flower, `@` and a year.
pub fn word_pw(i: usize) -> String {
    const WORDS: [&str; 4] = ["Marigold", "Bluefin", "Copperleaf", "Snowdrift"];
    format!("{}@{}", WORDS[i % 4], 2031 + i)
}

/// An invented cookie value.
pub fn tok(i: usize) -> String {
    format!("{}{}", &KEY_TAIL[i % 7..i % 7 + 14], 40 + i)
}

/// `(text, value)`: every byte of `value` (its last occurrence) must be hidden in
/// both modes, and Private must restore the text exactly.
pub fn positives() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut add = |template: &str, value: String| {
        out.push((template.replace("{}", &value), value));
    };
    // Prose links: might be, `,`, is, will be, was, changed … to, set it to, use, `:`.
    add("I think the password might be {} but I am not sure.", pw(0));
    add("Here you go: the password, {}, works on the router.", word_pw(0));
    add("Our API key, {}, expires next month.", key("pk_", 22));
    add("Keep the pin, 719406, away from the kids.", "719406".into());
    add("I changed my pin to 608153 yesterday.", "608153".into());
    add("The new password will be {} from Monday.", pw(1));
    add("The wifi password was {} last year.", pw(2));
    add("I changed the admin password on the NAS to {} this morning.", pw(3));
    add("For the vault password, set it to {} before the audit.", pw(4));
    add("For the staging API key use {} instead.", key("sk_", 24));
    add("Router password: use {} for now.", pw(5));
    add("Your password is {}", word_pw(1));
    add("Please enter your PIN, which is 552190, in the box.", "552190".into());
    add("The password {} was used to access the share.", pw(6));
    add("For example, a strong password could be {}.", pw(7));
    add("He has listed his password as {}. We have noted it.", word_pw(2));
    add("The files are protected with the password {} and can be opened.", pw(8));
    add("Log in with your username, jdoe77, and password, {}. Click next.", word_pw(3));
    add("Sign in at the portal using your password: {}", pw(9));
    add("Input the pin 663018 into the controller.", "663018".into());
    add("The breach exposed her pin 190524 and her account.", "190524".into());
    add("the token might be {} so try it", key("tk_", 20));
    // Mail, chat, logs.
    add("Hi Tom,\n\nthe Wi-Fi password is now {}.\n\nCheers,\nAnna", pw(10));
    add("[10:42] ana: the pwd might be {} lol", pw(11));
    add("2026-10-23 10:00:01 WARN user reset; new password will be {} (temp)", pw(12));
    add("> Bob wrote: the API key is {}, please rotate it", key("ak_", 21));
    // Markdown escapes.
    add("api\\_key: {}", key("live\\_", 20));
    add("The api\\_key is {}, the name assigned to it is billing.", key("AK", 18));
    add("**api\\_key**: {}", key("pk\\_", 22));
    add("access\\_token = {}", key("at_", 20));
    // Cookies.
    add("Cookie: sessionid={}; theme=dark", tok(0));
    add("Set-Cookie: user_session={}; Path=/; HttpOnly", tok(1));
    add("user_session={}; Path=/; Secure", tok(2));
    add("Include the http cookie sess_auth={} in the call.", tok(3));
    add("Your HTTP cookie: auth_token={} is essential.", tok(4));
    add("The cookie value was sid={}.", tok(5));
    add("GET /api HTTP/1.1\r\nHost: example.test\r\nCookie: sid={}\r\n\r\n", tok(6));
    add("WARN headers: Cookie: JSESSIONID={}; lang=en", tok(7));
    add("HTTP/1.1 200 OK\nset-cookie: __Host-sid={}; Path=/; Secure; SameSite=Lax\n", tok(8));
    // Public-corpus shapes (invented values): links after a few words, `such as`, cookies in prose.
    add("We have also noted his cookie as sess_token={}.", tok(10));
    add("Rest assured, your PIN, such as 480913, is stored safely.", "480913".into());
    add("Secure all devices with unique PINs, such as 774102, to prevent misuse.", "774102".into());
    add("The API key used in the request was {}. Rotate it.", key("rk_", 23));
    add("The password included in the request body was {}.", pw(15));
    add("The token ID is {} and the user is bob.", key("ti", 20));
    add("This commit was tracked using the http cookie sid={}; Path=/; HttpOnly.", tok(11));
    add("Change passwords and API keys, such as {}, every quarter.", key("ck_", 24));
    add("For the password field, use {}. If you need help, call us.", pw(16));
    add("The lessor and lessee agree to use {} as the password.", word_pw(5));
    add("Then the token {} was found in the repository.", key("gk", 22));
    add("le code PIN de votre compte (6620) et votre mot de passe", "6620".into());
    add("Don't forget to set your http cookie as pref_id={}; Path=/; Secure for later.", tok(12));
    add("A typical http cookie might look like this: auth_session={}; Path=/; HttpOnly.", tok(13));
    add("Only the PIN of 482019 unlocks it.", "482019".into());
    add("The API key change to {} was implemented on Friday.", key("ch_", 21));
    // French.
    add("Le mot de passe sera {} à partir de lundi.", pw(13));
    add("J'ai changé mon code PIN en 482117 hier.", "482117".into());
    add("Le mot de passe, {}, est dans le coffre.", word_pw(4));
    add("Le mot de passe était {} l'an dernier.", pw(14));
    add("Cookie : session={}", tok(9));
    add("Notre clé API : {}", key("fr_", 22));
    out
}

/// Lookalikes: no secret marker in Open, no secret token in Private.
pub fn negatives() -> Vec<String> {
    [
        "the key is to listen",
        "set it to true",
        "set it to false please",
        "set it to off",
        "set it to auto",
        "set it to default",
        "use the default",
        "Path=/",
        "Your password will be sent by email.",
        "The pin was wrong twice.",
        "the password, as you know, is private.",
        "Remember the password, then log in.",
        "I changed my password to something stronger.",
        "the token is valid for one hour",
        "The key, in short, is patience.",
        "Key takeaways: listen more.",
        "use the password manager",
        "Change the setting to enabled.",
        "Our cookie policy is simple.",
        "We use cookies to improve the site.",
        "The pin was set to the default value.",
        "The secret is out now.",
        "Le code est faux.",
        "Mon code PIN est oublié.",
        "The pin is in the drawer.",
        "Set it to 2 for the second mode.",
        "Use the code 2024 discount at checkout.",
        "The PIN pad is broken.",
        "the password for the guest account is on the fridge",
        "Use the token from yesterday.",
        "The cookie banner was closed.",
        "Your session cookie expires in 30 minutes.",
        "The PIN must have 6 digits.",
        "Enter a PIN between 4 and 8 digits.",
        "The API key is stored in the vault.",
        "api\\_key is optional",
        "Set-Cookie headers are stripped by the proxy.",
        "the http cookie is essential for login",
        "Use version 2.1 as the default.",
        "the token budget is 4096",
        "the key was under the mat",
        "my password is long and hard to guess",
        "PIN reset done, see ticket 4471.",
        "The password is the same as last time.",
        "Their API key, as noted, is in the vault.",
        "Passwords should be at least 12 characters.",
        "I will use it as the password hint.",
        "The code of conduct applies.",
        "Path=/ and Domain=example.org are cookie attributes.",
        "cookies such as the language preference",
        "Le mot de passe sera envoyé par e-mail.",
        "Le code PIN est à quatre chiffres.",
        "mdp oublié, merci de le réinitialiser",
        "The pin number is printed on the back.",
        "key=value pairs are listed below",
        "token: none",
        "password: ********",
        "The key to the 2024 plan is focus.",
        "Mail me at lena.ortiz@example.org about the password.",
        "The API key docs live at https://example.test/keys/v2.",
    ]
    .map(String::from)
    .to_vec()
}
