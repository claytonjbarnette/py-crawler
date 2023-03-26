from importlib import resources
from gsa_cert import GsaCert
from cert_results import CertificateResult
from typing import List, Dict
import logging

certs_to_process: List[GsaCert] = []
processed_certs: Dict[str, GsaCert] = {}


def get_sia_certs():
    pass


def main():
    # Configure Logging
    logger = logging.getLogger("py_crawler")
    logger.setLevel(logging.DEBUG)
    console_logger = logging.StreamHandler()
    console_logger.setLevel(logging.INFO)
    logger.addHandler(console_logger)
    logger.debug("logging DEBUG messages")

    # Start with Common
    common_file = resources.files("resources").joinpath("fcpcag2.crt")

    with common_file.open(mode="rb") as common_file:
        common_bytes = common_file.read()

    certs_to_process.append(GsaCert(input_bytes=common_bytes))

    while len(certs_to_process) > 0:
        # Add the SIA Certs from the first cert in the list
        cert_to_process = certs_to_process.pop(0)

        # Check to see if we've already processed this cert
        if cert_to_process.identifier not in processed_certs.keys():
            processed_certs[cert_to_process.identifier] = cert_to_process
            logger.info("Processing certificate %s", cert_to_process)
            certs_to_process.extend(cert_to_process.sia_certs())
        else:
            logger.info("Skipping already processed cert %s", cert_to_process)

    # We have walked the whole tree, now let's build some data structures.
    # First, we'll build the P7B with all the certs to support pathbuilding


if __name__ == "__main__":
    main()
