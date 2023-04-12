from __future__ import annotations

from typing import List

from asn1crypto import cms

import gsa_cert


class P7C:
    intermediate_certs: List[gsa_cert.GsaCert]

    def __init__(self, intermediate_certs: List[gsa_cert.GsaCert]) -> None:
        self.intermediate_certs = intermediate_certs

    def get_bytes(self) -> bytes:
        p7c_bytes = []
        p7c_certs = cms.CertificateSet()

        for gsaCert in self.intermediate_certs:
            p7c_certs.append(cms.CertificateChoices({"certificate": gsaCert.cert}))

        p7c_input = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": [],
                "encap_content_info": {
                    "content_type": "data",
                    "content": b"",
                },
                "certificates": p7c_certs,
                "signer_infos": [],
            }
        )

        p7c_obj = cms.ContentInfo(
            {
                "content_type": "signed_data",
                "content": p7c_input,
            }
        )

        p7c_bytes = p7c_obj.dump()

        return p7c_bytes
