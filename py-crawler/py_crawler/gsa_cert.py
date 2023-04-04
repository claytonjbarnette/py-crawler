from asn1crypto import x509, pem, cms, core, crl
from certvalidator import crl_client
from typing import Optional, List, OrderedDict, Any, Dict
import logging
import requests
import ldap3
from urllib.error import URLError
from ldap3.utils import uri as ldap_uri
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import subprocess
from pathlib import Path
import os
import base64

logger = logging.getLogger("py_crawler.gsa_cert")


@dataclass
class XiaResult:
    url: str
    status: str
    certs: List["GsaCert"]


class GsaCert:
    class Status(Enum):
        VALID = 0
        INVALID = 1
        REVOKED = 2
        REVOCATION_CHECK_FAILED = 3

    cert: x509.Certificate
    cert_dict: OrderedDict[str, Any]
    issuer: str
    subject: str
    status: Enum
    information_access_results: List[XiaResult] = []

    def get_status(self) -> Status:
        # If the certificate is expired or not yet valid, don't bother checking anything else
        if (
            "validity" in self.cert_dict.keys()
            and self.cert_dict["validity"]["not_before"] > datetime.now(tz=timezone.utc)
            and self.cert_dict["validity"]["not_after"] < datetime.now(tz=timezone.utc)
        ):
            return self.Status.INVALID
        else:
            # If the certificate is valid from a time perspective, run pathbuilder
            try:
                script_directory = Path(os.path.dirname(os.path.abspath(__file__)))
                pathbuilder_process = subprocess.run(
                    [
                        "java",
                        "-jar",
                        str(script_directory / "resources" / "pathbuilder-1.2.jar"),
                        "--output",
                        "short",
                        "--base64",
                        base64.b64encode(self.cert.dump()),
                    ],
                    check=True,
                    timeout=10,
                    capture_output=True,
                    encoding="utf8",
                )
            except subprocess.CalledProcessError as cpe:
                logging.critical("Calling pathbuilder failed: %s", cpe.stderr)
            except subprocess.TimeoutExpired:
                logging.critical("Process timed out.")

            return self.Status.VALID

    def __init__(
        self, input_bytes: bytes = b"", cert_dict: OrderedDict[str, Any] = OrderedDict()
    ) -> None:
        if len(cert_dict.keys()) > 0:
            self.cert_dict = cert_dict
        ## Note no real error handling here..
        elif len(input_bytes) > 0:
            cert_bytes: Optional[bytes]  # This is to prevent a linting error
            cert: x509.Certificate
            if pem.detect(input_bytes):
                # Ignoring type for next assignment due to obscure API behavior
                _, _, cert_bytes = pem.unarmor(input_bytes)  # type: ignore
                cert = x509.Certificate.load(cert_bytes)

                if cert.native is not None:
                    self.cert = cert
                    self.cert_dict = cert.native["tbs_certificate"]
            else:
                cert = x509.Certificate.load(input_bytes)
                if cert.native is not None:
                    self.cert = cert
                    self.cert_dict = cert.native["tbs_certificate"]
        else:
            raise Exception("Must provide a bitstring or parsed certificate dictionary.")

        subject = ""
        for rdn in reversed(self.cert_dict["subject"].keys()):
            for element in reversed(rdn):
                subject += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.subject = subject[:-1]

        issuer = ""
        for rdn in reversed(self.cert_dict["issuer"].keys()):
            for element in reversed(rdn):
                issuer += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.issuer = issuer[:-1]

        self.status = self.get_status()

    @property
    def identifier(self) -> str:
        identifier = str(self.cert_dict["issuer"]) + ":"
        identifier += str(self.cert_dict["serial_number"])
        return identifier

    def __str__(self) -> str:
        return self.issuer + " -> " + self.subject

    def get_info_access_certs_http(self, url: str) -> XiaResult:
        status: str = "UNKNOWN"
        found_certs: List["GsaCert"] = []
        logger.debug("Fetching P7C from %s", url)
        sia_response: requests.models.Response = requests.get(url)
        if sia_response:
            logger.info("Got P7C file from %s", url)
        else:
            logger.warning("Unable to get P7C file from %s", url)
            status = "ACCESS ERROR"
        # Process SIA data to extract certs

        if len(sia_response.content) > 0:
            p7c_content: cms.ContentInfo = cms.ContentInfo.load(sia_response.content)
            if (
                p7c_content.native is not None
                and "content" in p7c_content.native.keys()
                and "certificates" in p7c_content.native["content"].keys()
                and p7c_content.native["content"]["certificates"] is not None
            ):
                status = "OK"
                for cert in p7c_content.native["content"]["certificates"]:
                    found_certs.append(GsaCert(cert_dict=cert["tbs_certificate"]))
            else:
                status = "INVALID P7C"

        return XiaResult(url=url, status=status, certs=found_certs)

    def get_sia_ldap(self, url: str) -> List["GsaCert"]:
        # TODO - we can get the results from LDAP, but not sure how to process the crossCertificatePair
        found_certs: List[GsaCert] = []
        uri_components: Dict[str, str] = ldap_uri.parse_uri(url)
        # if uri_components["scheme"] != "ldap":
        #     logger.error("get_sia_ldap called, but schema is not ldap for %s", url)
        #     raise Exception("Invalid URL for LDAP")

        server_str = uri_components["host"]
        server_str += uri_components["port"] if uri_components["port"] is not None else ""

        search_filter = "(objectclass=*)"

        server = ldap3.Server(server_str, get_info=ldap3.SCHEMA)

        with ldap3.Connection(server_str, auto_bind="DEFAULT", check_names=True) as conn:
            conn.search(
                search_base=uri_components["base"],
                search_filter=search_filter,
                search_scope=ldap3.BASE,
                attributes=uri_components["attributes"],
            )
            if conn.response is not None:
                results: List[bytes] = conn.response[0]["raw_attributes"][
                    "crossCertificatePair;binary"
                ]

                for result in results:
                    pass  # crossCertificatePairs are funky to process..
                    # asn_cert_pair_sequence: core.Sequence = core.Sequence.load(result)
                    # logger.debug("CertificatePair: %s", asn_cert_pair_sequence.debug())
                    # found_certs.append(GsaCert(input_bytes=asn_cert_pair_sequence.dump()))

        return found_certs

    def information_access_certs(
        self,
    ) -> List["GsaCert"]:  # Quotes are required to satisfy the linter
        found_certs: List[GsaCert] = []
        for result in self.information_access_results:
            found_certs.extend(result.certs)
        return found_certs

    def get_information_access_results(self):
        extensions: List[OrderedDict[str, Any]] = []
        info_access_urls: List[str] = []
        self.information_access_results = []

        logger.info("Getting certs from SIA bundle in %s", self.__str__())

        # Check the status of the cert and return empty list if it's not valid
        if self.status != self.Status.VALID:
            logger.debug("Skipping invalid cert %s", self)

        ## Get the SIA URL, if it exists in the cert
        if "extensions" in self.cert_dict.keys():
            logger.debug("Processing extensions in %s", self.__str__())
            extensions.extend(self.cert_dict["extensions"])

        for extension in extensions:
            logger.debug("Reading extension %s in cert %s", extension["extn_id"], self)
            if extension["extn_id"] == "subject_information_access":
                logger.debug("Found SIA in cert %s", self)
                access_methods: List[OrderedDict[str, Any]] = extension["extn_value"]

                for access_method in access_methods:
                    if (
                        access_method["access_method"] == "ca_repository"
                        and "access_location" in access_method.keys()
                    ):
                        info_access_urls.append(access_method["access_location"])

            elif extension["extn_id"] == "authority_information_access":
                logger.debug("Found AIA in cert %s", self)
                access_methods = extension["extn_value"]

                for access_method in access_methods:
                    if (
                        access_method["access_method"] == "ca_issuers"
                        and "access_location" in access_method.keys()
                    ):
                        info_access_urls.append(access_method["access_location"])

        if len(info_access_urls) == 0:
            logger.info("No SIA/AIA URLs in certificate %s.", self)

        for info_access_url in info_access_urls:
            # Get the P7C file from the SIA URL
            if info_access_url.startswith("http://"):
                logger.debug("Found HTTP URL %s in %s", info_access_url, self)
                self.information_access_results.append(
                    self.get_info_access_certs_http(info_access_url)
                )

            elif info_access_url.startswith("ldap://"):
                logger.debug("Skipping LDAP URL %s in %s", info_access_url, self)
                pass  # There are some ldap SIAs, but do we support them?
                # found_certs.extend(self.get_sia_ldap(sia_url))
            else:
                logger.debug("Unknown URI scheme in URL %s", info_access_url)
