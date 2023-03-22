OrderedDict(
    [
        ("version", "v3"),
        ("serial_number", 193519736577664692092527670379836328600325585898),
        ("signature", OrderedDict([("algorithm", "sha384_rsa"), ("parameters", None)])),
        (
            "issuer",
            OrderedDict(
                [
                    ("country_name", "US"),
                    ("organization_name", "U.S. Government"),
                    ("organizational_unit_name", "FPKI"),
                    ("common_name", "Federal Common Policy CA G2"),
                ]
            ),
        ),
        (
            "validity",
            OrderedDict(
                [
                    (
                        "not_before",
                        datetime.datetime(2020, 10, 14, 13, 35, 12, tzinfo=datetime.timezone.utc),
                    ),
                    (
                        "not_after",
                        datetime.datetime(2040, 10, 14, 13, 35, 12, tzinfo=datetime.timezone.utc),
                    ),
                ]
            ),
        ),
        (
            "subject",
            OrderedDict(
                [
                    ("country_name", "US"),
                    ("organization_name", "U.S. Government"),
                    ("organizational_unit_name", "FPKI"),
                    ("common_name", "Federal Common Policy CA G2"),
                ]
            ),
        ),
        (
            "subject_public_key_info",
            OrderedDict(
                [
                    ("algorithm", OrderedDict([("algorithm", "rsa"), ("parameters", None)])),
                    (
                        "public_key",
                        OrderedDict(
                            [
                                (
                                    "modulus",
                                    880562878676943335860601389698008060030276762924475343883726995666702656420097392871719466015870162607792293664987550916328889518114909294085548241390485630526728112326438855008078808727359101285676466718642206797950692524430707910268939178579945165257220934941523022798364993795680944251081054151482326072375862550701869206982108515149174597705335636953720087336829201304808792343590620591298382840297992805572064200929586347955208339363807894975660130926690355334701357935828824887380565233741307941991685215920053675134203148514091313513260294159261075037100661229661970491281403958027270066816724177182675214480254301554281442035552974948148986816956036669442019952005274551642228921004822020923851927424415035090308776165908704366079298492161743697223627978474793742797551992336117954426748925570544045492719322398025164135830953312338437751357834286659565575554859400164018030983804722031145308256015513327667414379186462195804061724310481403085943279538218266189107000785805475917904356183318702772021555204021553779492994565315677434496438625158148473457955323118566940131068797456193383348234642916575873078523660666770752458791845133323053145297775850618889921251528800523093625390353353912471533926467101849041546538131207,
                                ),
                                ("public_exponent", 65537),
                            ]
                        ),
                    ),
                ]
            ),
        ),
        ("issuer_unique_id", None),
        ("subject_unique_id", None),
        (
            "extensions",
            [
                OrderedDict(
                    [
                        ("extn_id", "basic_constraints"),
                        ("critical", True),
                        ("extn_value", OrderedDict([("ca", True), ("path_len_constraint", None)])),
                    ]
                ),
                OrderedDict(
                    [
                        ("extn_id", "key_usage"),
                        ("critical", True),
                        ("extn_value", {"key_cert_sign", "crl_sign"}),
                    ]
                ),
                OrderedDict(
                    [
                        ("extn_id", "key_identifier"),
                        ("critical", False),
                        (
                            "extn_value",
                            b"\xf4'\\\xa9\xc3|G\xf4\xfa\xa6\xa7\xb0Y\x97\xaa\xdd5&\x17\xe3",
                        ),
                    ]
                ),
                OrderedDict(
                    [
                        ("extn_id", "subject_information_access"),
                        ("critical", False),
                        (
                            "extn_value",
                            [
                                OrderedDict(
                                    [
                                        ("access_method", "ca_repository"),
                                        (
                                            "access_location",
                                            "http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c",
                                        ),
                                    ]
                                )
                            ],
                        ),
                    ]
                ),
            ],
        ),
    ]
)
