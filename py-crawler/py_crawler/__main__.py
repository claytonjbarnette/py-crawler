from importlib import resources
from gsa_certificate import GsaCertificate
from certificate_graph import CertificateGraph
from graph_xml import GraphXML
from typing import List, Dict
import logging
from datetime import datetime
from xml.etree import ElementTree

from certs_to_p7b import P7C


def main():
    # Configure Logging
    logger = logging.getLogger("py_crawler")
    logger.setLevel(logging.DEBUG)
    console_logger = logging.StreamHandler()
    console_logger.setLevel(logging.DEBUG)
    logger.addHandler(console_logger)
    logger.debug("logging DEBUG messages")

    # Start with Common Policy Root
    common_file = resources.files("resources").joinpath("fcpcag2.crt")

    with common_file.open(mode="rb") as common_file:
        common_bytes = common_file.read()

    anchor = GsaCertificate(input_bytes=common_bytes)

    # Create a graph
    common_graph = CertificateGraph(anchor=anchor)
    common_graph.build_graph()

    # First lets create a report of the certs discovered
    logger.info("Creating report for this crawler run.")
    report_filename = "crawler-" + str(datetime.now()) + ".json"
    with open(report_filename, "w") as report:
        report.write(common_graph.report())

    # Next, produce a P7C
    logger.info("Creating P7B file")
    common_p7b = P7C(list(common_graph.edges.values()))

    with open("CACertificatesValidatingToFederalCommonPolicyG2.p7b", "wb") as common_p7b_file:
        common_p7b_file.write(common_p7b.get_p7b())

    # Finally, build the gexf output
    logger.info("building gexf - TODO")
    graph_xml = GraphXML(cert_graph=common_graph).tostring()
    if graph_xml is not None:
        with open("common_graph.gexf", "w") as graph_file:
            # Write file
            graph_file.write(graph_xml)


if __name__ == "__main__":
    main()
