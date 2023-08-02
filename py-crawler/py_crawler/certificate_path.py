from __future__ import annotations

from typing import TYPE_CHECKING

from .certs_to_p7b import P7C

if TYPE_CHECKING:
    from .gsa_certificate import GsaCertificate


class CertificatePath:
    # This represents a CertifiatePath - designed to speed up processing by caching potential paths

    # end_identifier is the path_identifer of the last element in the path - creating a longer path just requires us to copy this
    # and add the new "end"
    end_identifier: str
    # a list of the subject IDs in the path, so that we can pretty print the path
    description: list[str]
    # A list of the certs in the path
    certs: list[GsaCertificate]

    def __init__(self, certs: list[GsaCertificate]):
        if len(certs) > 0:
            self.certs = certs
            self.description = [cert.subject for cert in certs]
            self.end_identifier = certs[-1].subject

    @property
    def p7c(self) -> bytes:
        if len(self.certs) > 0:
            return P7C(intermediate_certs=list(self.certs)).get_bytes()
        else:
            return bytes()
