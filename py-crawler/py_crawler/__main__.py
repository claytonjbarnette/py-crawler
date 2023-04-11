from importlib import resources
from gsa_cert import GsaCert
from cert_graph import CertificateGraph
from typing import List, Dict
import logging
from datetime import datetime
import json


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

    anchor = GsaCert(input_bytes=common_bytes)
    # by definition the trust anchor is considered VALID
    anchor.status = GsaCert.Status.VALID

    common_graph = CertificateGraph(anchor=anchor)
    common_graph.build_graph()

    # First lets create a report of the certs discovered
    report_filename = "crawler-" + str(datetime.now())
    with open(report_filename, "w") as report:
        report.write(common_graph.report())


if __name__ == "__main__":
    main()
