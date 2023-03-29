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


OrderedDict(
    [
        (
            "tbs_certificate",
            OrderedDict(
                [
                    ("version", "v3"),
                    ("serial_number", 2832194736685444057757099746386612131328968851),
                    ("signature", OrderedDict([("algorithm", "sha256_rsa"), ("parameters", None)])),
                    (
                        "issuer",
                        OrderedDict(
                            [
                                ("domain_component", ["com", "evincible"]),
                                ("common_name", "Exostar Federated Identity Service Signing CA 4"),
                            ]
                        ),
                    ),
                    (
                        "validity",
                        OrderedDict(
                            [
                                (
                                    "not_before",
                                    datetime.datetime(
                                        2021, 10, 13, 19, 32, 40, tzinfo=datetime.timezone.utc
                                    ),
                                ),
                                (
                                    "not_after",
                                    datetime.datetime(
                                        2022, 10, 13, 19, 32, 40, tzinfo=datetime.timezone.utc
                                    ),
                                ),
                            ]
                        ),
                    ),
                    (
                        "subject",
                        OrderedDict(
                            [
                                ("domain_component", ["com", "evincible", "fis"]),
                                ("organization_name", "Rolls Royce PLC"),
                                ("organizational_unit_name", "ForumPass"),
                                ("common_name", "Derek Anti_1544(BIdentity)"),
                            ]
                        ),
                    ),
                    (
                        "subject_public_key_info",
                        OrderedDict(
                            [
                                (
                                    "algorithm",
                                    OrderedDict([("algorithm", "rsa"), ("parameters", None)]),
                                ),
                                (
                                    "public_key",
                                    OrderedDict(
                                        [
                                            (
                                                "modulus",
                                                21723960254605416393355117717495517867662220911749043163657245342008024907512811720642345250678685797767937880846541740006693770755321183234091300866602796078742107324464490168943544642368090047275583204672525222579522246458144883707845519548941985398788522350934505171544125607904185652739105174606069499949799396163425986282677678352816284416471812671870196885855898918716902886557332311789180716904637548233998060736985530810258842860587159509653303120455845431126917464027181958394642278353992198994772570632125368700189565991140187381344739048554557484048099225301651191539456546060672973866074363041924829610173,
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
                                    ("extn_id", "key_usage"),
                                    ("critical", True),
                                    ("extn_value", {"digital_signature"}),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "subject_alt_name"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        [
                                            "Derek.Anti@Rolls-Royce.com",
                                            OrderedDict(
                                                [
                                                    ("type_id", "1.3.6.1.4.1.311.20.2.3"),
                                                    ("value", "antid_1544@fis.evincible.com"),
                                                ]
                                            ),
                                        ],
                                    ),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "key_identifier"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        b"\xaa\xa1j&8LI\x84w\xf1f\x95\x8b\xf0J\xca\xae\xb7\x97\xce",
                                    ),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "authority_key_identifier"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        OrderedDict(
                                            [
                                                (
                                                    "key_identifier",
                                                    b"Y\xdb\x0f\x821\xed\x84\x8c\x10\x8eG\xd8\x8d\xd5\x8e\xed\xca\xfb1\n",
                                                ),
                                                ("authority_cert_issuer", None),
                                                ("authority_cert_serial_number", None),
                                            ]
                                        ),
                                    ),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "crl_distribution_points"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        [
                                            OrderedDict(
                                                [
                                                    (
                                                        "distribution_point",
                                                        [
                                                            "http://www.fis.evincible.com/fis/public/ESCA4.crl"
                                                        ],
                                                    ),
                                                    ("reasons", None),
                                                    ("crl_issuer", None),
                                                ]
                                            )
                                        ],
                                    ),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "authority_information_access"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        [
                                            OrderedDict(
                                                [
                                                    ("access_method", "ca_issuers"),
                                                    (
                                                        "access_location",
                                                        "http://www.fis.evincible.com/fis/public/ESCA4.p7c",
                                                    ),
                                                ]
                                            )
                                        ],
                                    ),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "extended_key_usage"),
                                    ("critical", False),
                                    ("extn_value", ["client_auth", "pkinit_kpclientauth"]),
                                ]
                            ),
                            OrderedDict(
                                [
                                    ("extn_id", "certificate_policies"),
                                    ("critical", False),
                                    (
                                        "extn_value",
                                        [
                                            OrderedDict(
                                                [
                                                    (
                                                        "policy_identifier",
                                                        "1.3.6.1.4.1.13948.1.1.1.8",
                                                    ),
                                                    ("policy_qualifiers", None),
                                                ]
                                            )
                                        ],
                                    ),
                                ]
                            ),
                        ],
                    ),
                ]
            ),
        ),
        ("signature_algorithm", OrderedDict([("algorithm", "sha256_rsa"), ("parameters", None)])),
        (
            "signature_value",
            b'F\xb2\x1b\xa9\xdc\xc1\xf1\xb4\x93\xc7\xcc\x0c\x02"Z\xc6\xf1\x19\x17\x1d\x9e\x10W\x15\\\xd2^Mw\xea\xf6\x94\xfe\xcf\xe0|\t\x15\xac\x7fga\xc1\x18\xe0\xef\xf9Hz\xa0\x83\xe3GHG\xf6\x1a\xb6\xc2\xda\xb70m\x94\xf75!eY\x81\xa9XQb\xa7W\xaf;\xb8$\x99\xa8T]7\xb7/\xacW\xc4qn\xc5g(3\xb0P\x86b\x92\x7f\x15\x8b\xfd\xad9\x07 \xe2\x80\x89\x9aY\xc3g\xe2\x06\x0c-\xa4c\xddU\xcc\xb7\x8d\xb2D\xfd|Z\xde\x12\x1fC\xbe\x90[\xb4\xaf\x87\xb6\xbc\xcd\x85\x1d\xdbE/q\xb3\xf0X\xa1\xe0\x9f\xb7\xeb\x8f\x1d^C\x00\xcb\xea\x1c\xcf\xffQf\x90\xd5\xaf\xd4\xc8\x88\xfeT\x9a`\xc5\xac6\xdf\xe2\xc5ag"\xa3t\xde\xab|6@y\xaf^\t\xc3wP\xceq\xde\xea\x8a\x07\xe4;UL\xa46\xcc\xef\x84$\x0eq\x94\xd1\xca\x9f\xd2\xf3Y4%\x03\x97Eh\xb5f\xd1\xfd0\xb7\x0c5s\xb5\xbd$\xfd\x15\xfd\xea\xe7\xbe\xe3\xda\x01',
        ),
    ]
)
