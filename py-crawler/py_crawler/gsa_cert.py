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
from enum import Enum, StrEnum
import subprocess
from pathlib import Path
import os
import base64
import json

logger = logging.getLogger("py_crawler.gsa_cert")


@dataclass
class XiaResult:
    url: str
    status: str
    certs: List["GsaCert"]


class GsaCert:
    class Status(StrEnum):
        VALID = "valid"
        INVALID = "invalid"
        REVOKED = "revoked"
        REVOCATION_CHECK_FAILED = "check_failed"
        UNCHECKED = "unchecked"

    cert: x509.Certificate
    cert_dict: OrderedDict[str, Any]
    issuer: str
    subject: str
    status: Status
    sia_results: List[XiaResult]
    aia_results: List[XiaResult]
    path: List["GsaCert"]  # The list of certs in the path to common

    def get_status(self, intermediate_certs: List["GsaCert"]) -> Status:
        p7c_obj: Optional[cms.ContentInfo] = None
        script_directory = Path(os.path.dirname(os.path.abspath(__file__)))
        logger.debug("Getting Certificate Status")
        # If the certificate is expired or not yet valid, don't bother checking anything else
        if (
            "validity" in self.cert_dict.keys()
            and self.cert_dict["validity"]["not_before"] > datetime.now(tz=timezone.utc)
            and self.cert_dict["validity"]["not_after"] < datetime.now(tz=timezone.utc)
        ):
            self.status = self.Status.INVALID
        else:
            # If the certificate is valid from a time perspective, run pathbuilder

            # First, create a cms SignedInfo object from the certs passed in as "intermediate certs"
            if len(intermediate_certs) > 0:
                logger.debug("Intermediate Certs passed to get_status for %s:", self)

                p7c_certs = cms.CertificateSet()

                for gsaCert in intermediate_certs:
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

            # Run pathbuilder
            logger.debug("Certificate within validity period, running pathbuilder")

            # Create arg list for pathbuilder
            pathbuilder_args = [
                "java",
                "-jar",
                str(script_directory / "resources" / "pathbuilder-1.2.jar"),
                "--output",
                "short",
                "--base64",
                base64.b64encode(self.cert.dump()),
            ]

            # Add intermediate certs if provided
            if p7c_obj is not None:
                pathbuilder_args.extend(
                    [
                        "--bundle-base64",
                        base64.b64encode(p7c_obj.dump()),
                    ]
                )
            logger.debug("Pathbuilder command arguments %s", pathbuilder_args)

            pathbuilder_process = None

            try:
                pathbuilder_process = subprocess.run(
                    pathbuilder_args,
                    check=True,
                    timeout=10,
                    capture_output=True,
                    encoding="utf8",
                )
            except subprocess.CalledProcessError as cpe:
                logger.critical("Calling pathbuilder failed: %s", cpe.stderr)
                self.status = self.Status.REVOCATION_CHECK_FAILED
            except subprocess.TimeoutExpired:
                logger.critical("Process timed out.")
                self.status = self.Status.REVOCATION_CHECK_FAILED

            if pathbuilder_process is not None:
                logger.debug(pathbuilder_process.stdout)
                pathbuilder_status = json.loads(pathbuilder_process.stdout)

                # If the path verification was successful, save the original cert list to the "path" field
                self.path = intermediate_certs

                if pathbuilder_status["result"] == "True":
                    self.status = self.Status.VALID
                elif pathbuilder_status["result"] == "False":
                    self.status = self.Status.REVOKED

            return self.status

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
            if type(self.cert_dict["subject"][rdn]) == str:
                subject += rdn + ":" + self.cert_dict["subject"][rdn] + ","
            elif type(self.cert_dict["subject"][rdn]) == list:
                for element in reversed(self.cert_dict["subject"][rdn]):
                    subject += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.subject = subject[:-1]

        issuer = ""
        for rdn in reversed(self.cert_dict["issuer"].keys()):
            if type(self.cert_dict["issuer"][rdn]) == str:
                issuer += rdn + ":" + self.cert_dict["issuer"][rdn] + ","
            elif type(self.cert_dict["issuer"][rdn]) == list:
                for element in reversed(self.cert_dict["issuer"][rdn]):
                    issuer += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.issuer = issuer[:-1]

        logger.info("Got certificate %s", self)

        self.status = self.Status.UNCHECKED
        self.sia_results = []
        self.aia_results = []
        self.path = []

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
            p7c: Optional[cms.ContentInfo] = None
            try:
                p7c = cms.ContentInfo.load(sia_response.content)
            except ValueError as ve:
                status = "Invalid P7C"

            status = "OK"

            if type(p7c) == cms.ContentInfo and p7c != None and p7c["content"] is not None:
                for cert in p7c["content"]["certificates"]:
                    logger.debug("found cert")
                    found_certs.append(GsaCert(input_bytes=cert.dump()))
        else:
            status = "Zero-byte P7C"

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

    def information_access_certs(self) -> List["GsaCert"]:
        # Get the certs if they haven't been retrieved yet
        if len(self.information_access_results) == 0:
            self.get_information_access_results()

        found_certs: List[GsaCert] = []
        for result in self.information_access_results:
            found_certs.extend(result.certs)
        return found_certs

    def get_sia_certs(self) -> List["GsaCert"]:
        sia_certs = []

        # If we haven't looked at the SIA, do it now.
        if len(self.sia_results) == 0:
            sia_values = [
                extension["extn_value"]
                for extension in self.cert_dict["extensions"]
                if extension["extn_id"] == "subject_information_access"
            ]

            for sia_value in sia_values:
                for value_dict in sia_value:
                    if (
                        "access_method" in value_dict.keys()
                        and value_dict["access_method"] == "ca_repository"
                        and "access_location" in value_dict.keys()
                    ):
                        sia_url = value_dict["access_location"]
                        logger.debug("Found SIA URL %s", sia_url)
                        self.sia_results.append(self.get_info_access_url(sia_url))

        # Get the certs from the SIAs
        for result in self.sia_results:
            sia_certs.extend(result.certs)

        logger.debug("Returning %s certs from SIA", len(sia_certs))
        return sia_certs

    def get_information_access_results(self):
        extensions: List[OrderedDict[str, Any]] = []
        info_access_urls: List[str] = []

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

    def get_info_access_url(self, info_access_url) -> XiaResult:
        if info_access_url.startswith("http://"):
            logger.debug("Found HTTP URL %s in %s", info_access_url, self)
            return self.get_info_access_certs_http(info_access_url)

        elif info_access_url.startswith("ldap://"):
            logger.debug("Skipping LDAP URL %s in %s", info_access_url, self)
            return XiaResult(info_access_url, "Unsupported schema", [])
        else:
            logger.debug("Unknown URI scheme in URL %s", info_access_url)
            return XiaResult(info_access_url, "Unsupported schema", [])

    def report_entry(self) -> Dict[str, Any]:
        report_entry = {}
        report_entry["subject"] = self.subject
        report_entry["issuer"] = self.issuer
        report_entry["status"] = self.status
        if self.status == self.Status.VALID:
            if len(self.path) > 0:
                report_entry["path-to-common"] = []
                for cert in self.path:
                    report_entry["path-to-common"].append(cert.subject)

            report_entry["sia-entries"] = {}
            for result in self.sia_results:
                report_entry["sia-entries"][result.url] = []
                for cert in result.certs:
                    report_entry["sia-entries"][result.url].append(cert.subject)

        return report_entry
