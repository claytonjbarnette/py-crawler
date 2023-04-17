from __future__ import annotations
from dataclasses import dataclass, field
import gsa_certificate
from certs_to_p7b import P7C


@dataclass
class CertificatePath:
    # This represents a CertifiatePath - designed to speed up processing by caching potential paths

    # end_identifier is the path_identifer of the last element in the path - creating a longer path just requires us to copy this
    # and add the new "end"
    end_identifier: str
    # a list of the subject IDs in the path, so that we can pretty print the path
    description: tuple[str]
    # A list of the certs in the path
    certs: tuple[gsa_certificate.GsaCertificate]
    # A p7c representation to help with certificate validation
    p7c: bytes = field(init=False)

    def __post_init__(self):
        if len(self.certs) > 0:
            self.p7c = P7C(intermediate_certs=list(self.certs)).get_bytes()
        else:
            self.p7c = bytes()
