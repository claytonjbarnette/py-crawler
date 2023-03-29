from gsa_cert import GsaCert
import logging

logger = logging.getLogger("py_crawler.processed_cert")


class CertificateResult:
    cert: GsaCert
    identifer: str

    def __init__(self, cert: GsaCert) -> None:
        self.cert = cert
        self.identifer = cert.identifier

    def report(self) -> None:
        for url in self.cert.aia_url_info:
            pass
