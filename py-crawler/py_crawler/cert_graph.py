from gsa_cert import GsaCert
import logging
from typing import List, Dict

logger = logging.getLogger("py_crawler.cert_graph")


class CertEdge:
    issuer: GsaCert
    subject: GsaCert


class CertificateGraph:
    anchor: GsaCert
    nodes: List[GsaCert]
    edges: List[CertEdge]

    def __init__(self, anchor: GsaCert) -> None:
        self.anchor = anchor
        self.nodes = []
        self.edges = []

    def build_graph(self):
        nodes_to_process: List[GsaCert] = [self.anchor]
        processed_nodes: Dict[str, GsaCert] = {}

        # nodes_to_process is a list of certs to be reviewed. When the cert is processed,
        # it is moved to the processed_nodes list. When new certs are discovered, they
        # are added to the list. When the nodes_to_process list is empty (i.e. all
        # certs have been discovered and processed) we exit.
        while len(nodes_to_process) > 0:
            # Add the SIA Certs from the first cert in the list
            node_to_process = nodes_to_process.pop(0)

            # Check to see if we've already processed this cert
            if node_to_process.identifier not in processed_nodes.keys():
                # If not, get the certs in it's SIA and AIA fields
                logger.info("Processing certificate %s", node_to_process)
                nodes_to_process.extend(node_to_process.information_access_certs())
                processed_nodes[node_to_process.identifier] = node_to_process
                self.nodes.append(node_to_process)

            else:
                logger.info("Skipping already processed cert %s", node_to_process)

        logger.info("Discovered %s certs", len(processed_nodes))

    def report(self) -> None:
        pass
