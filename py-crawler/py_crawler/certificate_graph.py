from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional, Set, Tuple

from .certificate_path import CertificatePath
from .gsa_certificate import GsaCertificate

logger = logging.getLogger("py_crawler.cert_graph")


class CertificateGraph:
    # The root and trust anchor
    anchor: GsaCertificate
    # The set of Issuer DNs
    nodes: Set[str]
    # All of the certificates in the graph
    edges: Dict[str, GsaCertificate]
    # Pre-cached paths to make processing faster
    paths: Dict[str, CertificatePath]
    # A list of certificates discovered but for which the path could not be built
    # (e.g. invalid, revoked, etc.)
    no_path: List[GsaCertificate]

    def __init__(self, anchor: GsaCertificate) -> None:
        # set the root to the trust anchor
        self.anchor = anchor

        # Initalize the empty data structures
        self.nodes = set()
        self.edges = {}
        self.no_path = []
        self.paths = {}

        # We add a special status for the root, since the "get_status" function doesn't make sense for
        # the trust anchor
        self.anchor.status = GsaCertificate.Status.VALID
        self.anchor.pathbuilder_result = {"result": "true", "details": "Trust Anchor"}

        # Create a "pseudo-path" for the root. The trust anchor is never actually in the path, but
        # we want to print it out, so we create a fake path with a name but no certs.
        self.anchor.path_to_anchor = CertificatePath(
            end_identifier=self.anchor.path_identifier,
            description=tuple([self.anchor.subject]),
            certs=tuple(),
        )

        self.paths[self.anchor.path_identifier] = self.anchor.path_to_anchor

    def get_path(self, leaf_cert: GsaCertificate) -> CertificatePath:
        # Provide a list of intermediate certs between the leaf and the root to facilitate
        # path validation
        logger.debug("Getting intermediates for %s", leaf_cert.subject)
        path: Optional[CertificatePath] = None

        # First, see if we were called with the root of the graph
        if leaf_cert.identifier == self.anchor.identifier:
            logger.debug("CertificateGraph.get_path called with root - skipping")
            return self.anchor.path_to_anchor
        else:
            # See if we have already identified the path of the certificate's issuer
            try:
                parent_path = self.paths[leaf_cert.path_parent_identifier]
                # create a new path ending at the leaf_cert
                path = CertificatePath(
                    end_identifier=leaf_cert.path_identifier,
                    description=parent_path.description + tuple([leaf_cert.subject]),
                    certs=parent_path.certs + tuple([leaf_cert]),
                )
                return path
            except KeyError as ke:
                # We don't have the parent's path

                # Log a warning, and add that info to the path processor result
                # field of the cert
                logger.warning("Found Cert in SIA without Parent: %s", leaf_cert.identifier)
                leaf_cert.pathbuilder_result[
                    "WARNING"
                ] = "Certificate is present in SIA of a CA that is not its issuer"
                raise Exception("Path from %s to root not found.", leaf_cert)

    def build_graph(self):
        # List of unprocessed certs - we will add to this as we discover new certs
        certs_to_process: List[GsaCertificate] = [self.anchor]

        # List of certs that have been definitively processed, success or failure
        processed_certs: Dict[str, GsaCertificate] = {}

        # List of certs that we attempted to process, but couldn't find the path for.
        # We will try a second pass when we've sorted everything else:
        purgatory_certs: List[GsaCertificate] = []

        logger.debug("Beginning processing of cert graph at %s", self.anchor.identifier)

        # certs_to_process is a list of certs to be reviewed. When the cert is processed,
        # it is moved to the processed_certs list. When new certs are discovered, they
        # are added to the list. When the certs_to_process list is empty (i.e. all
        # certs have been discovered and processed) we exit.
        while len(certs_to_process) > 0:
            # Add the first cert in the list, and remove it from certs_to_process
            cert_to_process = certs_to_process.pop(0)

            # Check to see if we've already processed this cert (May appear in multiple SIA/AIA fields)
            if cert_to_process.identifier not in processed_certs.keys():
                # IF not , process it
                logger.info("Processing certificate %s", cert_to_process)

                if cert_to_process != self.anchor and cert_to_process.is_trust_anchor():
                    cert_to_process.status = GsaCertificate.Status.NO_PATH
                    cert_to_process.pathbuilder_result[
                        "INFO"
                    ] = "Certificate is a trust anchor, but not the root of the graph"
                    # Create an empty Certificate Path
                    cert_to_process.path_to_anchor = CertificatePath(
                        end_identifier=cert_to_process.path_identifier,
                        description=tuple(),
                        certs=tuple(),
                    )
                    self.no_path.append(cert_to_process)

                if (
                    cert_to_process.status == GsaCertificate.Status.UNCHECKED
                ):  # get a path to pass to pathbuilder (pathbuilder will only validate)
                    try:
                        cert_to_process.path_to_anchor = self.get_path(leaf_cert=cert_to_process)
                        cert_to_process.status = cert_to_process.get_status(
                            proposed_path=cert_to_process.path_to_anchor
                        )
                    except Exception as e:
                        logger.debug(
                            "Path not found. Sending %s to purgatory", cert_to_process.identifier
                        )
                        purgatory_certs.append(cert_to_process)

                logger.debug(
                    "Status of Cert %s is %s",
                    cert_to_process.identifier,
                    str(cert_to_process.status),
                )
                if cert_to_process.status == GsaCertificate.Status.VALID:
                    self.nodes.add(cert_to_process.issuer)
                    self.nodes.add(cert_to_process.subject)
                    self.edges[cert_to_process.identifier] = cert_to_process
                    self.paths[cert_to_process.path_identifier] = cert_to_process.path_to_anchor

                    logger.debug(
                        "Adding SIA and AIA certificates from %s to certs_to_process.",
                        cert_to_process.identifier,
                    )
                    for next_cert in cert_to_process.get_sia_certs():
                        certs_to_process.append(next_cert)
                    for next_cert in cert_to_process.get_aia_certs():
                        certs_to_process.append(next_cert)
                elif cert_to_process.status == GsaCertificate.Status.UNCHECKED:
                    # We should only get here if the we could't find a path.
                    # We have already sent the cert to purgatory, so just log the event and move on
                    logger.debug(
                        "Sent %s to purgatory. Will reprocess in second pass.", cert_to_process
                    )
                else:
                    # We should only get here if we found a path, but something happened in processing
                    logger.debug("FAILED - sending %s to failed", cert_to_process.identifier)
                    self.no_path.append(cert_to_process)
                    logger.info("Skipping invalid or revoked cert %s", cert_to_process)

                processed_certs[cert_to_process.identifier] = cert_to_process

            else:
                logger.info("Skipping already processed cert %s", cert_to_process)

        # When we reach this point, every cert should be in processed_certs or purgatory_certs
        # We will take one more pass at purgatory certs, and send them to heaven or hell
        logger.debug("Processing %s certs in purgatory.", len(purgatory_certs))

        # To be extra sure we get everything, we're going to do one pas to build paths for all the certs in the list
        for cert_to_process in purgatory_certs:
            try:
                cert_to_process.path_to_anchor = self.get_path(leaf_cert=cert_to_process)
            except Exception as e:
                logger.debug(
                    "Path not found for %s during first round.", cert_to_process.identifier
                )

        # Now we'll try again - just in case we found the missing path
        for cert_to_process in purgatory_certs:
            try:
                if cert_to_process.path_to_anchor is not None:
                    cert_to_process.path_to_anchor = self.get_path(leaf_cert=cert_to_process)
                cert_to_process.status = cert_to_process.get_status(
                    proposed_path=cert_to_process.path_to_anchor
                )
            except Exception as e:
                logger.debug(
                    "Path not found for %s during second round. Sending to failed",
                    cert_to_process.identifier,
                )
                self.no_path.append(cert_to_process)

            if cert_to_process.status == GsaCertificate.Status.VALID:
                logger.debug("Success at last for %s", cert_to_process.identifier)
            else:
                # We get here when we couldn't get the cert to work on the second path
                logger.debug(
                    "Repeatedly failed to find a path. Sending %s to failed",
                    cert_to_process.identifier,
                )
                self.no_path.append(cert_to_process)

        logger.info(
            "Discovered %s certs. %s good and %s failed",
            len(self.edges) + len(self.no_path),
            len(self.edges),
            len(self.no_path),
        )

    def report(self) -> str:
        report = {}
        report["anchor"] = self.anchor.issuer
        report["issuers"] = []
        for node in self.nodes:
            report["issuers"].append(node)
        report["valid-certs"] = []
        for cert in self.edges.values():
            report["valid-certs"].append(cert.report_entry())
        report["bad-certs"] = []
        for cert in self.no_path:
            report["bad-certs"].append(cert.report_entry())
        report["found-paths"] = []
        for path in self.paths:
            report["found-paths"].append(self.paths[path].description)

        return json.dumps(report, indent=4)
