from asn1crypto import x509, pem, cms
from typing import Optional, List, OrderedDict, Tuple, Any
import logging
import requests

logger = logging.getLogger("py_crawler.gsa_cert")


class GsaCert:
    cert_dict: OrderedDict[str, Any]

    def __init__(self, input_bytes: bytes) -> None:
        ## Note no real error handling here..
        cert_bytes: Optional[bytes]  # This is to prevent a linting error
        cert = x509.Certificate
        if pem.detect(input_bytes):
            (_, _, cert_bytes) = pem.unarmor(input_bytes)
            cert = x509.Certificate.load(cert_bytes)
            if cert.native is not None:
                self.cert_dict = cert.native["tbs_certificate"]
        else:
            cert = x509.Certificate.load(input_bytes)
            if cert.native is not None:
                print(cert.native)
                self.cert_dict = cert.native["tbs_certificate"]

    def __init__(self, cert_dict: OrderedDict[str, Any]) -> None:
        self.cert_dict = cert_dict

    def __str__(self) -> str:
        issuer_cn = self.cert_dict

    def sia_certs(self) -> List["GsaCert"]:  # Quotes are required to satisfy the linter
        found_certs: List[GsaCert] = []
        extensions: List[OrderedDict[str, Any]] = []
        sia_url: Optional[str] = None

        logger.info("Getting cert from SIA bundle in %s", self.__str__())

        ## Get the SIA URL, if it exists in the cert
        if "extensions" in self.cert_dict.keys():
            logger.debug("Processing extensions in %s", self.__str__())
            extensions.extend(self.cert_dict["extensions"])

        for extension in extensions:
            logger.debug("Reading extension %s", extension["extn_id"])
            if extension["extn_id"] == "subject_information_access":
                access_methods: List[OrderedDict[str, Any]] = extension["extn_value"]

                for access_method in access_methods:
                    if (
                        access_method["access_method"] == "ca_repository"
                        and "access_location" in access_method.keys()
                    ):
                        sia_url = access_method["access_location"]

        if sia_url == None:
            logger.info("No SIA URL in certificate %s.", self.__str__())
            return found_certs

        logger.info("SIA URL found: %s", sia_url)

        # Get the P7C file from the SIA URL
        sia_response: requests.models.Response = requests.get(sia_url)

        if sia_response:
            logger.info("Got P7C file from %s", sia_url)
        else:
            logger.warning("Unable to get P7C file from %s", sia_url)
            return found_certs

        sia_p7c_bytes: bytes = sia_response.content

        p7c_content: cms.ContentInfo = cms.ContentInfo.load(sia_p7c_bytes)

        if p7c_content.native is not None:
            cert_dicts: List[x509.Certificate] = p7c_content.native["content"]

        for cert in cert_dicts:
            pass

        return found_certs
