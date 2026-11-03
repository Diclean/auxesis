// K-SECRET-TAIL-4 acceptance cases, shared by `tests/secret_tail4.rs` and the
// `secret_link` unit tests. (id, input, hide, clear): every non-whitespace byte of the
// last occurrence of each hide is masked; each clear stays in the gate output.

/// The PR1a cases.
const CASES: &[(&str, &str, &[&str], &[&str])] = &[
    ("H1", "My **password** is correct horse battery staple", &["correct horse battery staple"], &["My **password** is"]),
    ("H2", "My password is set to Tr0ub4dor horse battery staple", &["set to Tr0ub4dor horse battery staple"], &[]),
    ("H3", "Mon mot de passe est correct horse battery staple", &["correct horse battery staple"], &[]),
    ("H4", "My __password__ is correct horse battery staple", &["correct horse battery staple"], &[]),
    ("H5", "My **password** is set to Tr0ub4dor horse battery staple", &["set to Tr0ub4dor horse battery staple"], &[]),
    ("H6", "Mon mot-de-passe est Tr0ub4dor horse battery staple", &["Tr0ub4dor horse battery staple"], &[]),
    ("H7", "Mon **mot de passe** est Tr0ub4dor horse battery staple", &["Tr0ub4dor horse battery staple"], &[]),
    ("H8", "My **password** is red horse battery staple", &["red horse battery staple"], &[]),
    ("H9", "MOT DE PASSE ÉTAIT Tr0ub4dor horse", &["Tr0ub4dor horse"], &[]),
    // H10 is PR2 (tables): main does not mask it either.
    ("H13a", "Mon mot de passe est facile à retenir.", &["facile à retenir."], &[]),
    ("H13b", "Le mot de passe est difficile à mémoriser.", &["difficile à mémoriser."], &[]),
    ("H13c", "Le mot de passe est secret et personnel.", &["secret et personnel."], &[]),
    ("H13d", "Le mdp est utilisé pour se connecter.", &["utilisé pour se connecter."], &[]),
    ("S3a", "password is red horse\nbattery staple", &["red horse", "battery staple"], &[]),
    ("S3b", "password is\nred horse battery staple", &["red horse battery staple"], &[]),
    ("S3c", "password is \"red horse\nbattery staple\"", &["\"red horse", "battery staple\""], &[]),
    ("S3d", "password is red horse\n\nbattery staple", &["red horse"], &["battery staple"]),
    ("S5", "password=abc def=ghi", &["abc def=ghi"], &[]),
    ("S6a", "Mon code d'accès est red horse battery staple", &["red horse battery staple"], &[]),
    ("S6b", "Mon code d’accès est red horse battery staple", &["red horse battery staple"], &[]),
    ("S6c", "CODE D'ACCE\u{300}S est red horse battery staple", &["red horse battery staple"], &[]),
    ("S6d", "My **secret** is red horse battery staple", &["red horse battery staple"], &[]),
    ("S6g1", "My **passcode** is red horse battery staple", &["red horse battery staple"], &[]),
    ("S6g2", "**PIN**: 4821 9937", &["4821 9937"], &[]),
    ("S6g3", "`code secret` est red horse battery staple", &["red horse battery staple"], &[]),
    ("S7", "My password is red horse: battery staple", &["red horse: battery staple"], &[]),
    ("T1a", "password is red horse\nbattery: staple", &["red horse", "battery: staple"], &[]),
    ("T1b", "password: a\nb = c", &["a", "b = c"], &[]),
    ("T1c", "password is red horse\n\"battery\": \"staple\"", &["red horse", "\"battery\": \"staple\""], &[]),
    ("T1d", "password is red horse\n  - battery: staple", &["red horse", "- battery: staple"], &[]),
    ("T1e", "password is red horse\n[staple]", &["red horse", "[staple]"], &[]),
    ("T2", "password is red horse\u{E000}\nbattery staple", &["red horse\u{E000}", "battery staple"], &[]),
    ("T3c", "password is don't \"red. horse battery staple\"", &["don't \"red. horse battery staple\""], &[]),
    ("T3d", "password is \"red. horse battery staple", &["\"red. horse battery staple"], &[]),
    ("T3e", "password is “red «horse. Battery» staple”. Bye", &["“red «horse. Battery» staple”. Bye"], &[]),
    ("T3f", "password is \"red \"horse.\" Battery\" staple. Bye", &["\"red \"horse.\" Battery\" staple. Bye"], &[]),
    ("K1", "password: Fk3jQ9xZ2mAA\nusername: admin", &["Fk3jQ9xZ2mAA"], &["username: admin"]),
    ("K4", "password: red horse\nbattery: staple", &["red horse"], &["battery: staple"]),
    ("K5", "hosts:\n  - a.example\npassword: Fk3jQ9xZ2mAA\nuser: admin", &["Fk3jQ9xZ2mAA"], &["user: admin"]),
    ("M1", "password is abcd.", &["abcd."], &[]),
    ("M2", "password is red horse e.g. Battery", &["red horse e.g. Battery"], &[]),
    ("M3", "password is red horse. 🙂tail", &["red horse. 🙂tail"], &[]),
    ("M4", "password is red horse. שלום", &["red horse. שלום"], &[]),
    ("M5", "password is red horse。tail", &["red horse。tail"], &[]),
    ("M6", "\"password is red horse. Battery\"", &["red horse. Battery\""], &["\"password is"]),
    ("M7", "password is \"red \\\". Battery\"", &["\"red \\\". Battery\""], &[]),
    ("M8", "password is \"red \" horse. Battery\"", &["\"red \" horse. Battery\""], &[]),
    ("M9", "password is “red » horse. Battery”", &["“red » horse. Battery”"], &[]),
    ("M10", "password is red horse\n\u{200B}\nbattery staple", &["red horse", "\u{200B}", "battery staple"], &[]),
    ("M11", "password is red. \u{E000}tail", &["red. \u{E000}tail"], &[]),
    ("M12", "user: admin\npassword: red horse\n# battery staple", &["red horse", "# battery staple"], &["user: admin"]),
    ("M13", "user: admin\npassword: red horse\n[staple]", &["red horse", "[staple]"], &["user: admin"]),
    ("M15", "{\"password\":\"red \\\". Battery\"}", &["\"red \\\". Battery\"}"], &[]),
    ("M16", "user: admin\npassword: |\n  red horse\n\n  battery staple", &["red horse", "battery staple"], &["user: admin", "password: |"]),
    ("M17", "user: admin\npassword: >-\n  red horse\n\n  battery staple", &["red horse", "battery staple"], &["user: admin", "password: >-"]),
    ("M18", "~~~\npassword is red horse | x\n|---|---|\nbattery staple\n~~~", &["red horse | x", "|---|---|", "battery staple\n~~~"], &[]),
    ("M19", "password is red horse | x\n|---|\nbattery staple", &["red horse | x", "|---|", "battery staple"], &[]),
    ("M20", "password is red horse\r\nbattery staple", &["red horse", "battery staple"], &[]),
    ("M21", "password is 1.2 https://a.invalid/red.tail token=abcd", &["1.2 https://a.invalid/red.tail token=abcd"], &[]),
    ("M22", "export PASSWORD=red horse\nUSER=admin", &["red horse"], &["USER=admin"]),
    ("M23", "[auth]\npassword=red horse\nuser=admin", &["red horse"], &["[auth]", "user=admin"]),
    ("Q3", "password: red horse\nuser = admin", &["red horse", "user = admin"], &[]),
    ("Q4", "# db\nuser: admin\n# note\npassword: red horse\nport: 5432", &["red horse"], &["# db", "user: admin", "# note", "port: 5432"]),
    ("Q5", "[auth]\npassword=red horse\n# battery staple", &["red horse", "# battery staple"], &["[auth]"]),
    ("Q12a", "password is red horse\n\u{A0}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("Q12b", "password is red horse\n\u{3000}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("Q13", "~~~\nDB_PASSWORD=red horse\nDB_USER=admin\n~~~", &["red horse", "DB_USER=admin\n~~~"], &["~~~"]),
    ("Q14", "user: admin\npassword:\n  red horse\n\n  battery staple\nport: 5432", &["red horse", "battery staple"], &["user: admin", "port: 5432"]),
    ("N5", "password is red horse\n\u{A0}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("N6", "password is red horse\n\u{2028}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("N7", "password is red horse\n\u{2029}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("N8", "password is red horse\n\u{C}\nbattery staple", &["red horse", "battery staple"], &[]),
    ("N9", "password is red horse\n\u{E000}\nbattery staple", &["red horse", "\u{E000}", "battery staple"], &[]),
    ("N10", "password is red horse\n\u{FFFD}\nbattery staple", &["red horse", "\u{FFFD}", "battery staple"], &[]),
    ("N12a", "password: red horse\n\"\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\u{E000}\": ok", &["red horse"], &["\": ok"]),
    ("N12b", "password: red horse\n\"\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\": ok", &["red horse"], &["\": ok"]),
    ("N12c", "password: red horse\n\"xxxxxxxxxxxxxxxxxxxxxx\": ok", &["red horse"], &["\"xxxxxxxxxxxxxxxxxxxxxx\": ok"]),
    ("KB10", "hosts:\n  - a: b\npassword: Fk3jQ9xZ2mAA\nuser: admin", &["Fk3jQ9xZ2mAA"], &["hosts:", "- a: b", "user: admin"]),
];

/// The PR1b cases (the ownership pass: quotes, fences, block scalars, key blocks,
/// nested openers) and PR1c's flow regions: R5, R6, R8, R9, the r5
/// comment cases C1–C6, the extra checks E1–E4 and the
/// flow continuations in a key block F1–F4.
const PR1B_CASES: &[(&str, &str, &[&str], &[&str])] = &[
    ("M14", "export PASSWORD=\"red horse\n# battery staple\nUSER=admin\"", &["\"red horse", "# battery staple", "USER=admin\""], &[]),
    ("Q1", "password: red horse\nnote: 'see\nbattery staple", &["red horse", "note: 'see", "battery staple"], &[]),
    ("Q2", "password: red horse\nnote: \"see\nbattery staple\"", &["red horse", "note: \"see", "battery staple\""], &[]),
    ("Q6", "\"password is red horse\n\nbattery\" ok\n\nBye", &["red horse", "battery\" ok"], &["Bye"]),
    ("Q7", "'Tis the season.\n\nMy password is hunter2\n\nBye", &["hunter2", "Bye"], &["'Tis the season."]),
    ("Q8", "password is «red horse”\n\nBye", &["«red horse”", "Bye"], &[]),
    ("Q9", "password is \"red \\\"\n\nhorse\" ok\n\nBye", &["\"red \\\"", "horse\" ok"], &["Bye"]),
    ("Q10", "password is \"red \" horse\n\nbattery\" ok\n\nBye", &["\"red \" horse", "battery\" ok"], &["Bye"]),
    ("Q11", "密码：「red horse\n\nbattery」\n\nBye", &["「red horse", "battery」"], &["Bye"]),
    ("N1", "passwords:\n  - first: red horse\nuser: admin", &["- first: red horse"], &["user: admin"]),
    ("N2", "passwords:\n  - first: red horse\n\n  - second: battery staple\nuser: admin", &["- first: red horse", "- second: battery staple"], &["user: admin"]),
    ("N3", "password:\n  first: red horse\n  second: battery staple\nuser: admin", &["first: red horse", "second: battery staple"], &["user: admin"]),
    ("N4", "«“password is red horse”»\n\nBye", &["«“", "red horse”»"], &["Bye"]),
    ("N11", "password is don't O'Brien\n\nbattery staple", &["don't O'Brien"], &["battery staple"]),
    ("KB1", "password:\n  - first: red horse\nuser: admin", &["- first: red horse"], &["user: admin"]),
    ("KB2", "secret:\n  db: red horse\n  # battery staple\n  [x]\nuser: admin", &["db: red horse", "# battery staple", "[x]"], &["user: admin"]),
    ("KB3", "db:\n  passwords:\n    main:\n      value: red horse\n  user: admin\nport: 5432", &["main:", "value: red horse"], &["db:", "user: admin", "port: 5432"]),
    ("KB4", "password:\n  red horse\n\n\n    battery: staple\nuser: admin", &["red horse", "battery: staple"], &["user: admin"]),
    ("KB5", "password: red horse\n  battery: staple\nuser: admin", &["red horse", "battery: staple"], &["user: admin"]),
    ("KB6", "- password:\n    - red horse\n- user: admin", &["- red horse"], &["- user: admin"]),
    ("KB7", "password: {\n  \"first\": \"red horse\"\n}\nuser: admin", &["\"first\": \"red horse\"", "}"], &["user: admin"]),
    ("KB8", "  password:\n\tred horse\n  user: admin", &["red horse", "user: admin"], &[]),
    ("KB9", "db:\n    password:\n      red horse\n  user: admin", &["red horse", "user: admin"], &["db:"]),
    ("KB11", "password:\n  red horse\n\nuser: admin", &["red horse"], &["user: admin"]),
    ("KB12", "password:\n  - \"red\nbattery staple\"\nuser: admin", &["- \"red", "battery staple\"", "user: admin"], &[]),
    ("O1", "«“‘password is red horse’”»\n\nBye", &["«“‘", "red horse’”»"], &["Bye"]),
    ("O2", "«“a” password is red horse»\n\nBye", &["«", "red horse»"], &["“a”", "Bye"]),
    ("O3", "«“password is red horse”»\n\n«“pin: 4821”» ok\n\nBye", &["red horse”»", "4821”» ok"], &["Bye"]),
    ("O4", "«“password is red horse”»", &["red horse”»"], &["«“"]),
    ("A1", "password is 'red 12' horse\n\nbattery staple", &["'red 12' horse"], &["battery staple"]),
    ("A2", "The pole is 12' high.\n\nMy password is hunter2\n\nBye", &["hunter2"], &["The pole is 12' high.", "Bye"]),
    ("A3", "password is 'red 12'horse\n\nbattery staple'\n\nBye", &["'red 12'horse", "battery staple'"], &["Bye"]),
    // D-2 finds: structure inside a region before the value, once its opener is masked.
    ("D1", "~~~\n“passwd“: red horse\n~~~\n\nBye", &["red horse", "~~~"], &["Bye"]),
    ("D2", "\"x\n~~~\npassword is red horse\nend\" ok\n\nBye", &["red horse", "end\" ok"], &["Bye"]),
    // L1–L3: PR1b narrows PR1a here (regions 1 and 2); PR1a hid the last lines.
    ("L1", "password: Fk3jQ9xZ2mAA\nscript: |\n  FOO=bar\nuser: admin", &["Fk3jQ9xZ2mAA"], &["script: |", "FOO=bar", "user: admin"]),
    ("L2", "password:\n  a = red horse\nuser: admin", &["a = red horse"], &["user: admin"]),
    ("L3", "password: red horse\n  battery\nuser: admin", &["red horse", "battery"], &["user: admin"]),
    ("R1", "  passwords:\n\t- first: red horse\n  user: admin", &["- first: red horse", "user: admin"], &[]),
    ("R2", "passwords:\r\n  - first: red horse\r\n\r\n  - second: battery staple\r\nuser: admin", &["- first: red horse", "- second: battery staple"], &["user: admin"]),
    ("R3", "- passwords: red horse\n  user: admin\n- next: ok", &["red horse", "user: admin"], &["- next: ok"]),
    ("R4", "db:\n    passwords:\n      first: red horse\n  user: admin", &["first: red horse", "user: admin"], &[]),
    ("R5", "{\n\"passwords\": {\n\"first\": \"red horse\",\n\"second\": \"battery staple\"\n},\n\"user\": \"admin\"\n}", &["\"first\": \"red horse\",", "\"second\": \"battery staple\"", "},"], &["\"user\": \"admin\""]),
    ("R6", "{\n\"passwords\": [\n{\n\"first\": \"red horse\"\n}\n],\n\"user\": \"admin\"\n}", &["\"first\": \"red horse\"", "],"], &["\"user\": \"admin\""]),
    ("R7", "passwords:\n  ~~~\n  red horse\n\nuser: admin\n\nBye", &["~~~", "red horse", "user: admin", "Bye"], &[]),
    ("R8", "{\n\"passwords\": [\"red ] horse\",\n\"battery staple\"],\n\"user\": \"admin\"\n}", &["[\"red ] horse\",", "\"battery staple\"],"], &["\"user\": \"admin\""]),
    ("R9", "passwords: [red horse\n}\nuser: admin\n\nBye", &["[red horse", "user: admin", "Bye"], &[]),
    ("C1", "passwords: { # }\nfirst: red horse,\nsecond: battery staple\n}\nuser: admin", &["{ # }", "first: red horse,", "second: battery staple", "}"], &["user: admin"]),
    ("C2", "passwords: [ // ]\n\"red horse\"\n]\nuser: admin", &["[ // ]", "\"red horse\""], &["user: admin"]),
    ("C3", "passwords: { \"a#b\": \"red horse\" }\nuser: admin", &["{ \"a#b\": \"red horse\" }"], &["user: admin"]),
    ("C4", "passwords: {a: red#horse}\nuser: admin", &["{a: red#horse}"], &["user: admin"]),
    ("C5", "passwords: { # {\nfirst: red horse\n}\nuser: admin", &["first: red horse", "}"], &["user: admin"]),
    ("C6", "{\n\"passwords\": { // }\n\"first\": \"red horse\",\n\"second\": \"battery staple\"\n},\n\"user\": \"admin\"\n}", &["\"first\": \"red horse\",", "\"second\": \"battery staple\""], &["\"user\": \"admin\""]),
    ("E1", "passwords: [\"red \\\"] horse\",\n\"battery staple\"]\nuser: admin", &["[\"red \\\"] horse\",", "\"battery staple\"]"], &["user: admin"]),
    ("E2", "\"passwords\": \"{ red horse\",\n\"user\": \"admin\"", &["\"{ red horse\","], &["\"user\": \"admin\""]),
    ("E3", "passwords: {\n\"passwords\": \"red horse\",\n\"second\": \"battery staple\"\n}\nuser: admin", &["\"passwords\": \"red horse\",", "\"second\": \"battery staple\""], &["user: admin"]),
    ("E4", "passwords: [{[{\n\"red horse\"\n}]}\n]\nuser: admin", &["\"red horse\"", "}]}"], &["user: admin"]),
    ("F1", "passwords:\n  first: {\nfirst: red horse\n} [\nsecond: battery staple\n]\nuser: admin", &["first: red horse", "second: battery staple"], &[]),
    ("F2", "passwords:\n  first: [\nfirst: red horse\n] {\nsecond: battery staple\n}\nuser: admin", &["first: red horse", "second: battery staple"], &[]),
    ("F3", "passwords:\r\n  first: {\r\nfirst: red horse\r\n} [\r\nsecond: battery staple\r\n]\r\nuser: admin", &["first: red horse", "second: battery staple"], &[]),
    ("F4", "passwords:\n  first: {\nfirst: red horse\n} [\nsecond: battery staple", &["first: red horse", "second: battery staple"], &[]),
];

/// The PR2 cases: the `|` link and the column form.
const PR2_CASES: &[(&str, &str, &[&str], &[&str])] = &[
    ("H10", "| password | Tr0ub4dor horse |", &["Tr0ub4dor horse"], &["password"]),
    ("S1a", "| | password |\n|---|---|\n| bank | hunter2 horse |", &["hunter2 horse"], &["bank"]),
    ("S1b", "|   | password |\n|---|---|\n| bank |    |", &[], &["bank"]),
    ("S1c", "| password | | hunter2 horse |", &["hunter2 horse"], &[]),
    ("S4a", "| password | required horse battery staple |", &["required horse battery staple"], &[]),
    ("S4b", "| password | in horse battery staple |", &["in horse battery staple"], &[]),
    ("S4c", "| password | now horse battery staple |", &["now horse battery staple"], &[]),
    ("S4da", "| key | value |\n|---|---|\n| password | required horse battery staple |", &["required horse battery staple"], &["key", "value"]),
    ("S4db", "| key | value |\n|---|---|\n| password | in horse battery staple |", &["in horse battery staple"], &["key", "value"]),
    ("S4dc", "| key | value |\n|---|---|\n| password | now horse battery staple |", &["now horse battery staple"], &["key", "value"]),
    ("S6e", "| code d'accès | red horse battery staple |", &["red horse battery staple"], &[]),
    ("S6f", "| site | Secret |\n|---|---|\n| bank | red horse battery staple |", &["red horse battery staple"], &["bank"]),
    // Ragged rows, a row with no pipe, edge pipes off, CRLF, an escaped pipe.
    ("TB1", "site | PIN | note\n:--|:-:|--:\nbank | 4821 9937 | ok\nshop | 7700\nmail", &["4821 9937", "7700"], &["bank", "shop", "mail"]),
    // D-2 find: no table, but the rest of the header after `site` meets the 1-cell
    // delimiter in the residue view; `site` is masked to the line end.
    ("TB3", "| password | site | PIN |\n| --- |\n| bank |\nmore words", &["site | PIN"], &["bank", "more words"]),
    // D-2 stress finds (Private refused before the fix): the rest of a row after a masked
    // value reads from column 0; a short cell merges with the masked value after it; a
    // header inside a run reads as a table once the outer header is masked away.
    ("SR1", "| pw |\n| --- |\n| secrets | red horse |. Thanks", &["red horse", ". Thanks"], &[]),
    ("SR2", "| password |\n| --: |\n口令: |\n  red horse\n\nBye", &["red horse"], &["Bye"]),
    ("SR3", "| site | password | user |\n|---|---|---|\n| bank | hunter2 | admin |\n| pin |\n| - |\n| 4821 9937 |", &["hunter2", "4821 9937"], &["bank", "admin"]),
    ("TB2", "| user | password |\r\n|---|---|\r\n| admin | red \\| horse |\r\n| guest | battery staple |", &["red \\| horse", "battery staple"], &["admin", "guest"]),
    // A pipe-free delimiter (one cell) under a one-cell header with a pipe: a table.
    ("TP1", "| password |\n---\n| red horse |", &["red horse"], &[]),
    ("TP2", "| password |\n:---:\n| red horse |\n\nBye", &["red horse"], &["Bye"]),
    ("TP3", "| password |\r\n---\r\n| red horse |\r\n", &["red horse"], &[]),
    ("TP4", "| password |\n --- \n| red horse |\nbattery staple\n\nBye", &["red horse", "battery staple"], &["Bye"]),
    ("TP5", "password |\n-\nbattery staple", &["battery staple"], &[]),
    // No table: a heading rule under a plain line, a YAML document marker, a header of
    // two cells.
    ("TP6", "Password reset\n---\nbattery staple", &[], &["battery staple"]),
    ("TP7", "---\nuser: admin\n---\nbattery staple", &[], &["battery staple"]),
    ("TP8", "| password | site |\n---\n| bank | battery staple |", &[], &["battery staple"]),
];

/// No table rule applies (P2-1): a pipe-free delimiter under a plain line, YAML
/// markers, M18 and M19. `scan` gives the same spans with and without PR2.
const PR2_SAME: &[&str] = &[
    "Password reset\n---\nbattery staple",
    "password: red horse\n---\nuser: admin",
    "---\npassword: red horse\n---\nuser: admin\n",
    "| note |\n---\npassword staple",
    "~~~\npassword is red horse | x\n|---|---|\nbattery staple\n~~~",
    "password is red horse | x\n|---|\nbattery staple",
];

/// P2-2: a key cell that opens an owned region (each quote pair, closed and unclosed,
/// a key block, a flow, a block scalar), or a fence right under a row. Returns the
/// text and the parts that must be masked.
fn owned_cells() -> Vec<(String, Vec<&'static str>)> {
    const PAIRS: &[(&str, &str)] = &[
        ("\"", "\""), ("'", "'"), ("\u{201D}", "\u{201D}"), ("\u{2019}", "\u{2019}"),
        ("\u{201C}", "\u{201D}"), ("\u{201E}", "\u{201C}"), ("\u{2018}", "\u{2019}"),
        ("\u{201A}", "\u{2018}"), ("\u{AB}", "\u{BB}"), ("\u{BB}", "\u{AB}"),
        ("\u{2039}", "\u{203A}"), ("\u{203A}", "\u{2039}"), ("\u{300C}", "\u{300D}"),
        ("\u{300E}", "\u{300F}"),
    ];
    let head = "| password |\n|---|\n";
    let mut cases = Vec::new();
    for &(open, close) in PAIRS {
        cases.push((format!("{head}| {open}red |\nhorse{close}\n\nBye"), vec!["red", "horse"]));
        cases.push((format!("{head}| {open}red |\nhorse\n\nBye"), vec!["red", "horse"]));
        cases.push((format!("| pin |\n---\n{open}red |\nhorse{close}"), vec!["red", "horse"]));
    }
    for (text, hide) in [
        ("secret: red\n  horse staple", vec!["red", "horse staple"]),
        ("token: {\n  red horse\n}", vec!["red horse"]),
        ("note: |\n  red horse", vec!["red horse"]),
        ("| red horse |\n```\nbattery staple\n```", vec!["red horse"]),
    ] {
        cases.push((format!("{head}{text}"), hide));
    }
    cases
}


/// K-REFUSALS: Private refused these (main 62c75fd0), never a leak. Masking turns a
/// neighbour of a clear quote into a stand-in and a line break, so in the residue view
/// that quote pairs differently and owns the rest. Every quote pair nested in another
/// before a key, between clear `''`; a quote opener in a non-key cell of a table row
/// (with and without the edge pipe, before another column); main's closing-line mask.
fn refusal_cases() -> Vec<(String, String, Vec<&'static str>, Vec<&'static str>)> {
    const PAIRS: &[(&str, &str)] = &[("\"", "\""), ("'", "'"), ("“", "”"), ("„", "“"), ("‘", "’"), ("‚", "’"), ("«", "»"), ("»", "«"), ("‹", "›"), ("›", "‹"), ("”", "”"), ("’", "’"), ("「", "」"), ("『", "』")];
    let mut cases = Vec::new();
    for &(outer, outer_close) in PAIRS {
        for &(inner, inner_close) in PAIRS {
            let text = format!("''{outer}{outer}{inner}passwd is red horse{inner_close}{outer_close}{outer_close}''\n\nBye");
            cases.push((format!("KR1 {outer}{inner}"), text, vec!["red horse"], vec!["passwd is"]));
        }
        for row in [
            "| site | password |\n|---|---|\n| {q}foo | red horse |",
            "| site | password |\n|---|---|\n| {q}foo | red horse",
            "| site | password | note |\n|---|---|---|\n| {q}foo | red horse | ok |",
            "site | password\n---|---\n{q}foo | red horse |\n\nBye",
        ] {
            let text = row.replace("{q}", outer);
            cases.push((format!("KR2 {text:?}"), text, vec!["red horse"], vec!["site"]));
        }
    }
    // Main masks `AFTER` past the quote end (the closing line, whole): kept, never narrowed.
    let after = "| password |\n|---|\n| \"red |\nhorse\" AFTER\n\nBYE";
    cases.push(("KR3".to_owned(), after.to_owned(), vec!["\"red", "horse\" AFTER"], vec!["BYE"]));
    cases
}

/// The PR1a cases built by code: H11, H12, T3a, T3b, R2 and B1–B4 in their U+E000,
/// U+FFFD and `x` forms.
fn built_cases() -> Vec<(String, String, Vec<String>, Vec<String>)> {
    let s = |text: &str| text.to_owned();
    let long = "a".repeat(1025);
    let words = "word ".repeat(110);
    let mut cases = vec![
        (s("H11"), format!("Mon mdp est {long}"), vec![long.clone()], vec![s("Mon mdp est")]),
        (s("H12"), format!("Mon mot de passe est {long}"), vec![long.clone()], vec![]),
        (s("T3a"), format!("password is \"red. {}battery staple\"", "horse ".repeat(30)), vec![format!("\"red. {}battery staple\"", "horse ".repeat(30))], vec![]),
        (s("T3b"), format!("password is {}\"red. horse battery staple\"", "a ".repeat(45)), vec![format!("{}\"red. horse battery staple\"", "a ".repeat(45))], vec![]),
        (s("R2a"), format!("password is {words}. Next"), vec![format!("{words}. Next")], vec![]),
        (s("R2b"), format!("password is {words}\n\nNext"), vec![words.clone()], vec![s("Next")]),
        (s("R2c"), s("password is red horse\nbattery staple\nmore words"), vec![s("red horse"), s("battery staple"), s("more words")], vec![]),
    ];
    for form in ["\u{E000}", "\u{FFFD}", "x"] {
        for (id, n, quote, config) in [("B1", 64, "\"", true), ("B2", 65, "\"", false), ("B3", 64, "", true), ("B4", 65, "", false)] {
            let line = format!("{quote}{}{quote}: ok", form.repeat(n));
            let (hide, clear) = if config { (vec![s("red horse")], vec![line.clone()]) } else { (vec![s("red horse"), line.clone()], vec![]) };
            cases.push((format!("{id} {form:?}"), format!("password: red horse\n{line}"), hide, clear));
        }
    }
    cases
}

/// P2: a passphrase planted after a key, a mark and a link, in prose (one line or
/// wrapped over lines, a zero-width-only or NBSP-only line), a config entry (one
/// separator, with Structure lines and Block children around it, or continued on a
/// Structure line) or a quoted form. Never K4. Returns the text, the passphrase's
/// byte range and its words.
fn planted() -> impl proptest::strategy::Strategy<Value = (String, std::ops::Range<usize>, Vec<String>)> {
    use proptest::prelude::*;
    let word = prop_oneof![
        4 => "[A-Za-z0-9]{1,8}",
        2 => "[A-Za-z0-9.!?:,=;'\"é😀אב密\u{200B}]{1,6}",
        1 => Just("\\\"".to_owned()),
    ];
    let prose_key = prop::sample::select(&["password", "Password", "PASSWORD", "mot de passe", "mdp", "passphrase", "api key", "pwd", "passcode", "jelszó", "wagwoord", "secret key"][..]);
    let entry_key = prop::sample::select(&["password", "DB_PASSWORD", "api_key", "passphrase", "PIN", "\"password\"", "token"][..]);
    let mark = prop::sample::select(&["", "**", "__", "`", "~~"][..]);
    let link = prop::sample::select(&[" is", " was", " est", " are", ":", " :", " =", " for the portal is", " de la banque est"][..]);
    let sep = prop::sample::select(&[": ", "=", " = ", " := "][..]);
    let lead = prop::sample::select(&["", "Ref: ", "Hi,\nmy "][..]);
    let trail = prop::sample::select(&["", ". Thanks", "\n\nBye", "\nsee you"][..]);
    let gap = prop::sample::select(&["\n", "\n\u{200B}\n", "\n\u{A0}\n", " "][..]);
    let quote = prop::sample::select(&[("\"", "\""), ("'", "'"), ("“", "”"), ("«", "»"), ("「", "」")][..]);
    (("[A-Za-z0-9]{4,8}", prop::collection::vec(word, 0..6)), 0..5usize, (prose_key, entry_key, mark, link), (sep, lead, trail, gap), (quote, 1..6usize)).prop_map(
        |((first, mut words), layout, (key, entry_key, mark, link), (sep, lead, trail, gap), (quote, cut))| {
            words.insert(0, first);
            let cut = cut.min(words.len());
            let (head, tail) = (words[..cut].join(" "), words[cut..].join(" "));
            let wrap = if link.contains(['=', ':']) { " is" } else { link };
            let (before, value, after) = match layout {
                0 => (format!("{lead}{mark}{key}{mark}{link} "), format!("{head} {tail}"), trail.to_owned()),
                1 => (format!("{lead}{mark}{key}{mark}{wrap} "), format!("{head}{gap}{tail}"), trail.to_owned()),
                2 => (format!("# app\nhosts{sep}\n  - a.example\nuser{sep}admin\n{entry_key}{sep}"), format!("{head} {tail}"), format!("\n[next]\nport{sep}5432")),
                3 => (format!("user{sep}admin\n{entry_key}{sep}"), format!("{head}\n# {tail}"), format!("\nport{sep}5432")),
                _ => (format!("{lead}{key}{link} {}", quote.0), format!("{head} {tail}"), format!("{} ok{trail}", quote.1)),
            };
            (format!("{before}{value}{after}"), before.len()..before.len() + value.len(), words)
        },
    )
}

/// P8: a passphrase owned by a quote (every pair kind, nested 1–3 deep, with an escape
/// and an ambiguous quote inside; opened before or after the key; closed, unclosed or
/// mismatched), a fence, a block scalar, a key block (singular or plural key, empty or
/// inline value, children of any shape at deeper indents) or a flow value (nested 1–3,
/// fields at any indent, brackets in quotes, a comment), each across 0–3 blank lines.
/// Returns the text, the ranges that must be masked (the words, the openers before the
/// value when text follows, the tail when unclosed) and the words.
fn owned() -> impl proptest::strategy::Strategy<Value = (String, Vec<std::ops::Range<usize>>, Vec<String>)> {
    use proptest::prelude::*;
    const PAIRS: &[(&str, &str)] = &[("\"", "\""), ("'", "'"), ("“", "”"), ("„", "“"), ("‘", "’"), ("‚", "’"), ("«", "»"), ("»", "«"), ("‹", "›"), ("›", "‹"), ("”", "”"), ("’", "’"), ("「", "」"), ("『", "』")];
    let words = prop::collection::vec("[a-z][a-z0-9]{3,7}", 1..5);
    let gaps = prop::collection::vec(prop::sample::select(&[" ", "\n", "\n\n", "\n\n\n", "\n\n\n\n"][..]), 5);
    let quotes = prop::collection::vec(prop::sample::select(PAIRS), 1..4);
    let key = prop::sample::select(&["password", "passwords", "secret", "secrets", "DB_PASSWORD", "api_key", "tokens", "- password"][..]);
    let child = prop::collection::vec((prop::sample::select(&["  ", "    ", "  - ", "\t"][..]), 0..7usize), 5);
    (0..5usize, words, gaps, quotes, (0..3usize, any::<bool>(), any::<bool>()), (key, child)).prop_map(
        |(layout, words, gaps, quotes, (end, before, follows), (key, child))| {
            let (mut text, mut hide) = (String::new(), Vec::new());
            let put = |text: &mut String, hide: &mut Vec<std::ops::Range<usize>>, part: &str, masked: bool| {
                let at = text.len();
                text.push_str(part);
                if masked {
                    hide.push(at..text.len());
                }
            };
            let tail = if follows { " ok\n\nBye" } else { "" };
            match layout {
                0 => {
                    // `end`: 0 closed, 1 unclosed, 2 mismatched innermost closer.
                    if !before {
                        text.push_str("password is ");
                    }
                    for (open, _) in &quotes {
                        put(&mut text, &mut hide, open, before && follows && end == 0);
                        text.push_str("x ");
                    }
                    if before {
                        text.push_str("password is ");
                    }
                    for (n, word) in words.iter().enumerate() {
                        put(&mut text, &mut hide, word, true);
                        text.push_str(if n + 1 < words.len() { [gaps[n], " \\\" ", " \" "][n % 3] } else { "" });
                    }
                    for (n, (open, close)) in quotes.iter().enumerate().rev() {
                        let wrong = if *open == "「" { "»" } else { "」" };
                        text.push_str(match end { 0 => close, 1 => "", _ if n + 1 == quotes.len() => wrong, _ => close });
                        text.push_str(" x");
                    }
                    put(&mut text, &mut hide, tail, end != 0);
                }
                1 => {
                    let fence = if before { "~~~\npassword is " } else { "My password is\n```\n" };
                    put(&mut text, &mut hide, &fence[..3], before && follows);
                    text.push_str(&fence[3..]);
                    for (n, word) in words.iter().enumerate() {
                        put(&mut text, &mut hide, word, true);
                        text.push_str(gaps[n]);
                    }
                    text.push_str(if before { "\n~~~" } else { "\n```" });
                    text.push_str(if follows { "\n\nBye" } else { "" });
                }
                2 | 3 => {
                    let indent = if before { "  " } else { "" };
                    text.push_str(if before { "db:\n" } else { "user: admin\n" });
                    text.push_str(&format!("{indent}{key}:{}\n", [" |", "", " red"][if layout == 2 { 0 } else { end }]));
                    for (n, word) in words.iter().enumerate() {
                        let (lead, shape) = child[n];
                        let lead = if layout == 2 { "  " } else { lead };
                        let (head, after) = [("a: ", ""), ("- ", ""), ("# ", ""), ("[", "]"), ("", ""), ("x = ", ""), ("\"q\": \"", "\"")][if layout == 2 { 4 } else { shape }];
                        text.push_str(&format!("{indent}{lead}{head}"));
                        put(&mut text, &mut hide, word, true);
                        text.push_str(after);
                        text.push_str(&"\n".repeat(gaps[n].matches('\n').count().max(1)));
                    }
                    text.push_str(&format!("{indent}user: admin"));
                }
                _ => {
                    let opens: Vec<&str> = quotes.iter().map(|(open, _)| if open.len() % 2 == 0 { "{" } else { "[" }).collect();
                    text.push_str(&format!("{{\n\"{key}\": {}{}\n", opens.concat(), if before { " # }" } else { "" }));
                    for (n, word) in words.iter().enumerate() {
                        let (lead, shape) = child[n];
                        text.push_str(["", lead][usize::from(follows)]);
                        let (head, after) = [("\"f\": \"", "\","), ("\"a] { ", "\","), ("", ",")][shape % 3];
                        text.push_str(head);
                        put(&mut text, &mut hide, word, true);
                        text.push_str(after);
                        text.push_str(&"\n".repeat(gaps[n].matches('\n').count().max(1)));
                    }
                    let closes: String = opens.iter().rev().map(|open| if *open == "{" { "}" } else { "]" }).collect();
                    text.push_str(&format!("{closes},\n\"user\": \"admin\"\n}}"));
                }
            }
            (text, hide, words)
        },
    )
}

/// P4: a random table (edge pipes per row, blank, padded and key header cells, ragged
/// rows, rows with no pipe, a valid or malformed delimiter, inside a fence or not).
/// Returns the text and the ranges that must be masked: each data cell of ≥ 4
/// non-whitespace chars under a key header of a valid table outside a fence.
fn tables() -> impl proptest::strategy::Strategy<Value = (String, Vec<std::ops::Range<usize>>)> {
    use proptest::prelude::*;
    const KEYS: &[&str] = &["password", "Secret", "PIN", "api_key", "mot de passe"];
    let head = prop::sample::select(&["password", "Secret", "PIN", "api_key", "mot de passe", "site", "user", "note", "", "   "][..]);
    let cell = prop_oneof![3 => "[a-z0-9]{1,8}( [a-z0-9]{1,8}){0,2}", 1 => Just(String::new()), 1 => Just("    ".to_owned())];
    let edges = (any::<bool>(), any::<bool>());
    let row = (prop::collection::vec(cell, 0..6), edges, 0..8usize);
    let delim = prop::sample::select(&["---", ":--", "--:", ":-:", " - "][..]);
    (prop::collection::vec(head, 1..5), edges, prop::collection::vec(delim, 1..5), 0..4usize, prop::collection::vec(row, 0..6), any::<bool>()).prop_map(
        |(heads, edges, delims, malformed, rows, fenced)| {
            // A leading pipe when asked, or when the first cell would read as an indent; a
            // final one when asked, or when the last cell is blank (else it is dropped).
            let lead = |cells: &[&str], lead: bool| lead || cells.len() < 2 || cells[0].trim().is_empty();
            let line = |cells: &[&str], (first, trail): (bool, bool)| {
                let trail = trail || cells.last().is_some_and(|cell| cell.trim().is_empty());
                format!("{}{}{}", if lead(cells, first) { "| " } else { "" }, cells.join(" | "), if trail { " |" } else { "" })
            };
            // 0: valid; 1: one cell short or long; 2: a bad cell; 3: no pipe at all.
            let mut cells: Vec<&str> = (0..heads.len()).map(|n| delims[n % delims.len()]).collect();
            match malformed {
                1 if cells.len() > 1 => _ = cells.pop(),
                1 => cells.push("---"),
                2 => cells[0] = "-x-",
                _ => {}
            }
            // A pipe-free delimiter is valid under a one-cell header (it has a pipe).
            let delimiter = if malformed == 3 { delims[0].to_owned() } else { line(&cells, (true, true)) };
            let valid = (malformed == 0 || malformed == 3 && heads.len() == 1) && !fenced;
            let mut text = String::from(if fenced { "```\n" } else { "" });
            text += &line(&heads, edges);
            text += "\n";
            text += &delimiter;
            let mut hide = Vec::new();
            for (cells, edges, plain) in rows {
                text += "\n";
                if plain == 0 || cells.is_empty() {
                    // A row with no pipe: one cell, the whole line.
                    text += "plain row";
                    if valid && KEYS.contains(&heads[0]) {
                        hide.push(text.len() - 9..text.len());
                    }
                    continue;
                }
                let cells: Vec<&str> = cells.iter().map(String::as_str).collect();
                text += if lead(&cells, edges.0) { "| " } else { "" };
                for (n, cell) in cells.iter().enumerate() {
                    if n > 0 {
                        text += " | ";
                    }
                    let key = heads.get(n).is_some_and(|head| KEYS.contains(head));
                    if valid && key && cell.chars().filter(|ch| !ch.is_whitespace()).count() >= 4 {
                        hide.push(text.len()..text.len() + cell.len());
                    }
                    text += cell;
                }
                text += if edges.1 { " |" } else { "" };
            }
            text += if fenced { "\n```\n\nBye" } else { "\n\nBye" };
            (text, hide)
        },
    )
}
