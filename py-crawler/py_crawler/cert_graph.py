from gsa_cert import GsaCert
import logging
from typing import List, Dict, Set
from dataclasses import dataclass
import json

logger = logging.getLogger("py_crawler.cert_graph")


class CertificateGraph:
    root: GsaCert
    nodes: Set[str]
    edges: Dict[str, GsaCert]
    paths: Dict[str, List[GsaCert]]
    failed: List[GsaCert]

    def __init__(self, anchor: GsaCert) -> None:
        # set the root to the trust anchor
        self.root = anchor

        # We add a special status for the root, since the "get_status" function doesn't make sense for
        # the trust anchor
        self.root.status = GsaCert.Status.VALID
        self.root.pathbuilder_result = {"result": "true", "details": "Trust Anchor"}

        # Initalize the empty data structures
        self.nodes = set()
        self.edges = {}
        self.failed = []
        self.paths = {}

    def get_intermediate_certs(self, leaf_cert: GsaCert) -> List[GsaCert]:
        # Provide a list of intermediate certs between the leaf and the root to facilitate
        # path validation
        logger.debug("Getting intermediates for %s", leaf_cert.subject)
        path: List[GsaCert] = []

        # See if we already have a path for this CA
        if leaf_cert.identifier in self.paths.keys():
            path = self.paths[leaf_cert.identifier]
        # If not, we'll have to create the path
        else:
            # If you call the function with the root, or one of the root's immediate children,
            # the list of intermediates is empty.
            if leaf_cert.identifier == self.root.identifier:
                # If you call the function with the root cert itself, we return an empty list
                # The anchor is not part of the path, so there is no need to store it here
                pass
            elif (
                leaf_cert.issuer == self.root.subject
                and leaf_cert.cert.authority_key_identifier_value
                == self.root.cert.key_identifier_value
            ):
                # If you call the function with one of the root cert's immediate children, we
                # register the child by key ID as an intermediate but return an empty list
                if leaf_cert.cert.key_identifier_value is not None:
                    self.paths[leaf_cert.cert.key_identifier_value] = [leaf_cert]
                else:
                    # No Key ID so we'll use subject name
                    self.paths[leaf_cert.cert.subject] = [leaf_cert]
            else:
                # Otherwise, create a new list with the leaf_cert appended to the parent cert's intermediate list.
                # Graphs are always built from the root out, so for any cert submitted, the list of
                # intermediates from the next node up should already exist.
                path.extend(self.paths[leaf_cert.issuer])
                path.append(leaf_cert)
                self.paths[leaf_cert.subject] = path

        if len(path) == 0:
            logger.debug("No Intermediate Certs")
        else:
            logger.debug("Intermediate certs %s", ":".join(str([cert for cert in path])))
        return path

    def build_graph(self):
        certs_to_process: List[GsaCert] = [self.root]
        processed_certs: Dict[str, GsaCert] = {}

        # certs_to_process is a list of certs to be reviewed. When the cert is processed,
        # it is moved to the processed_certs list. When new certs are discovered, they
        # are added to the list. When the certs_to_process list is empty (i.e. all
        # certs have been discovered and processed) we exit.
        while len(certs_to_process) > 0:
            # Add the SIA Certs from the first cert in the list
            cert_to_process = certs_to_process.pop(0)

            # Check to see if we've already processed this cert
            if cert_to_process.identifier not in processed_certs.keys():
                # If not, get the certs in it's SIA and AIA fields
                logger.info("Processing certificate %s", cert_to_process)

                if cert_to_process.status == GsaCert.Status.UNCHECKED:
                    # get a path to pass to pathbuilder (pathbuilder will only validate)
                    intermediate_certs = self.get_intermediate_certs(leaf_cert=cert_to_process)
                    cert_to_process.status = cert_to_process.get_status(
                        intermediate_certs=intermediate_certs
                    )

                if cert_to_process.status == GsaCert.Status.VALID:
                    logger.info("Certificate valid - fetching certificates from SIA")
                    self.nodes.add(cert_to_process.issuer)
                    self.nodes.add(cert_to_process.subject)
                    self.edges[cert_to_process.identifier] = cert_to_process
                    for next_cert in cert_to_process.get_sia_certs():
                        certs_to_process.append(next_cert)
                else:
                    self.failed.append(cert_to_process)
                    logger.info("Skipping invalid or revoked cert %s", cert_to_process)

                processed_certs[cert_to_process.identifier] = cert_to_process

            else:
                logger.info("Skipping already processed cert %s", cert_to_process)

        logger.info("Discovered %s certs", len(processed_certs))

    def report(self) -> str:
        report = {}
        report["anchor"] = self.root.issuer
        report["issuers"] = []
        for node in self.nodes:
            report["issuers"].append(node)
        report["valid-certs"] = []
        for cert in self.edges.values():
            report["valid-certs"].append(cert.report_entry())
        report["bad-certs"] = []
        for cert in self.failed:
            report["bad-certs"].append(cert.report_entry())

        return json.dumps(report)
