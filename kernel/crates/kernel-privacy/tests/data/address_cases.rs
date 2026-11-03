// Address fixtures shared by `tests/addresses.rs` and
// `tests/address_differential.rs` (ADDR-DET-1, ADDR-DET-2). Every address is invented.

/// (input, every substring that must be masked whole).
const CASES: &[(&str, &[&str])] = &[
    // English: UK, US, IE, AU, CA, ZA.
    (
        "Send it to 221B Baker Street, London NW1 6XE please.",
        &["221B Baker Street, London NW1 6XE"],
    ),
    (
        "Our office: 1600 Pennsylvania Ave NW, Washington, DC 20500",
        &["1600 Pennsylvania Ave NW, Washington, DC 20500"],
    ),
    (
        "Flat 3, 14 High St, Bristol BS1 4DJ",
        &["Flat 3, 14 High St, Bristol BS1 4DJ"],
    ),
    (
        "Ship to 42 Maple Road, Springfield, IL 62704",
        &["42 Maple Road, Springfield, IL 62704"],
    ),
    ("Write to PO Box 1234, Cork", &["PO Box 1234"]),
    (
        "The new place is 9 Hollin Close, Harrowmere.",
        &["9 Hollin Close"],
    ),
    (
        "Apt 4B, 350 Fifth Avenue, New York, NY 10118",
        &["Apt 4B, 350 Fifth Avenue, New York, NY 10118"],
    ),
    (
        "Deliver to Unit 7, 18 Quill Row, Leeds LS1 4AP.",
        &["Unit 7, 18 Quill Row, Leeds LS1 4AP"],
    ),
    ("My address is 42 maple road.", &["42 maple road"]),
    (
        "Mara Ellison\n12 Lantern Gardens\nGlenfallow GL5 3QT\nUnited Kingdom",
        &["12 Lantern Gardens\nGlenfallow GL5 3QT"],
    ),
    ("Postcode: SW1A 1AA", &["SW1A 1AA"]),
    (
        "Ottawa office: 80 Wellington St, Ottawa, ON K1A 0A2",
        &["80 Wellington St, Ottawa, ON K1A 0A2"],
    ),
    (
        "Our Dublin office is at 7 Merrion Square, Dublin 2, D02 X285.",
        &["7 Merrion Square", "D02 X285"],
    ),
    (
        "Send to 12 George St, Sydney NSW 2000",
        &["12 George St, Sydney NSW 2000"],
    ),
    (
        "Level 3, 100 Hay Street, Perth WA 6000",
        &["Level 3, 100 Hay Street, Perth WA 6000"],
    ),
    (
        "Office: 12 Long Street, Cape Town, 8001",
        &["12 Long Street, Cape Town, 8001"],
    ),
    ("Private Bag X12, Pretoria", &["Private Bag X12"]),
    (
        "Mail to P.O. Box 4521, Austin, TX 78701",
        &["P.O. Box 4521, Austin, TX 78701"],
    ),
    (
        "Invoice to 500 Oak Drive, Denver CO 80202 by Friday.",
        &["500 Oak Drive, Denver CO 80202"],
    ),
    (
        "Meet me at 10 Downing Street at 3 pm.",
        &["10 Downing Street"],
    ),
    (
        "Flat 3, 22 Tanner's Yard, 00000 Glenfallow",
        &["Flat 3, 22 Tanner's Yard, 00000 Glenfallow"],
    ),
    (
        "Find us at 18&nbsp;Lantern Lane, Mistvale.",
        &["18&nbsp;Lantern Lane"],
    ),
    (
        "3rd Floor, 25 Old Broad Street, London EC2N 1HQ",
        &["3rd Floor, 25 Old Broad Street, London EC2N 1HQ"],
    ),
    (
        "We moved to 3 Mossgate Park, 00000 Harrowmere last week.",
        &["3 Mossgate Park, 00000 Harrowmere"],
    ),
    // French.
    (
        "Envoyez au 12 rue des Lilas, 75011 Paris.",
        &["12 rue des Lilas, 75011 Paris"],
    ),
    (
        "Adresse : 3 bis avenue Victor Hugo, 69003 Lyon",
        &["3 bis avenue Victor Hugo, 69003 Lyon"],
    ),
    (
        "Bât. B, 8 boulevard de la Liberté, 13001 Marseille",
        &["Bât. B, 8 boulevard de la Liberté, 13001 Marseille"],
    ),
    ("BP 456, 31000 Toulouse", &["BP 456, 31000 Toulouse"]),
    (
        "Rendez-vous 27 place du Marché, 44000 Nantes",
        &["27 place du Marché, 44000 Nantes"],
    ),
    (
        "14, allée des Vanilles, 00000 Malvoisine",
        &["14, allée des Vanilles, 00000 Malvoisine"],
    ),
    (
        "Le colis part du 9, impasse du Hérisson demain.",
        &["9, impasse du Hérisson"],
    ),
    (
        "On se retrouve au 18 quai des Brumes ?",
        &["18 quai des Brumes"],
    ),
    (
        "J'habite au 5 rue de l'Église, 67000 Strasbourg.",
        &["5 rue de l'Église, 67000 Strasbourg"],
    ),
    (
        "Camille Exemple\n12 chemin des Vignes\n33000 Bordeaux\nFrance",
        &["12 chemin des Vignes\n33000 Bordeaux"],
    ),
    ("Livraison : 7 rue des lilas", &["7 rue des lilas"]),
    (
        "Siège : 40 avenue des Champs-Élysées, 75008 Paris Cedex 08",
        &["40 avenue des Champs-Élysées, 75008 Paris Cedex 08"],
    ),
    ("CS 70001, 92000 Nanterre", &["CS 70001, 92000 Nanterre"]),
    ("Mon adresse :\n75011 Paris", &["75011 Paris"]),
    (
        "Appartement 12, 3 rue Lafayette, 75009 Paris",
        &["Appartement 12, 3 rue Lafayette, 75009 Paris"],
    ),
    (
        "Courrier au 123 rue de Rivoli 75001 Paris svp",
        &["123 rue de Rivoli 75001 Paris"],
    ),
    (
        "Le bureau : 2 place Bellecour, 69002 Lyon.",
        &["2 place Bellecour, 69002 Lyon"],
    ),
    // Hungarian, Slovene, Afrikaans, German.
    (
        "Cím: 1051 Budapest, Kossuth Lajos utca 12.",
        &["1051 Budapest, Kossuth Lajos utca 12."],
    ),
    (
        "Csillag utca 3. fsz. 2., 00000 Ködvölgy",
        &["Csillag utca 3. fsz. 2., 00000 Ködvölgy"],
    ),
    (
        "Naslov: Slovenska cesta 12, 1000 Ljubljana",
        &["Slovenska cesta 12, 1000 Ljubljana"],
    ),
    (
        "Prešernov trg 2, 1000 Ljubljana",
        &["Prešernov trg 2, 1000 Ljubljana"],
    ),
    (
        "Ons kantoor is by Kerkstraat 12, 7600 Stellenbosch.",
        &["Kerkstraat 12, 7600 Stellenbosch"],
    ),
    (
        "18 Lanternlaan, 00000 Misvallei",
        &["18 Lanternlaan, 00000 Misvallei"],
    ),
    ("Posbus 1234, Pretoria", &["Posbus 1234"]),
    (
        "Erf 88, Silwerboomstraat, 00000 Nuwelandsdal",
        &["Erf 88, Silwerboomstraat, 00000 Nuwelandsdal"],
    ),
    ("Postfach 12 34 56", &["Postfach 12 34 56"]),
    ("Ek bly by 18 Kiewiet-laan.", &["18 Kiewiet-laan"]),
];

/// Texts with no address and no other value: every one stays byte-identical in
/// private mode, and the address rule alone finds nothing in them.
const CLEAR: &[&str] = &[
    "The total is 12 30 EUR.",
    "See you at 10 Main for the meeting.",
    "Upgrade to version 2.4.1 Release today.",
    "Invoice line: 2 x Street lamp, 45.00 EUR",
    "Invoice: 3 x Garden Gnome @ 12.50",
    "The meeting is on 12 March 2026 at 14:30.",
    "Le rendez-vous est le 3 mai à 10 h.",
    "Apple Park is in Cupertino.",
    "the 3 of us in Rue",
    // Decision: a road name without a house number is not an address.
    "Baker Street is busy today.",
    "We walked down Oxford Street.",
    "Total: 15000 EUR",
    "Les 3 places disponibles sont réservées.",
    "Il reste 2 cours de maths.",
    "2026 Annual Report",
    "In 2025 Paris hosted the games.",
    "Order ID 48213 shipped.",
    "Room 12 is free at 3 pm.",
    "Terminal 5 Gate A10 opens at 9.",
    "Top 10 Ways to save.",
    "Chapter 3 Hill Climbing",
    "We bought 3 red street lamps.",
    "BP 2023 results were strong.",
    "Growth:\n15000 Users",
    "Windows 2000 Server",
    "Print it on A4 paper, 80 g.",
    "Le 12 rue est fermé.",
];
