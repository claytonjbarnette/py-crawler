from importlib import resources
from gsa_cert import GsaCert
from cert_results import CertificateResult
from typing import List, Dict
import logging
from datetime import datetime
import json

certs_to_process: List[GsaCert] = []
processed_certs: Dict[str, GsaCert] = {}


def get_sia_certs():
    pass


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

    certs_to_process.append(GsaCert(input_bytes=common_bytes))

    # Certs_to_process is a list of certs to be reviewed. When the cert is processed,
    # it is moved to the processed cert list. When new certs are discovered, they
    # are added to the list. When the certs_to_process list is empty (i.e. all
    # certs have been discovered and processed) we exit.
    while len(certs_to_process) > 0:
        # Add the SIA Certs from the first cert in the list
        cert_to_process = certs_to_process.pop(0)

        # Check to see if we've already processed this cert
        if cert_to_process.identifier not in processed_certs.keys():
            # If not, get the certs in it's SIA and AIA fields
            logger.info("Processing certificate %s", cert_to_process)
            certs_to_process.extend(cert_to_process.information_access_certs())
            processed_certs[cert_to_process.identifier] = cert_to_process

        else:
            logger.info("Skipping already processed cert %s", cert_to_process)

    logger.info("Discovered %s certs", len(processed_certs))

    # We have walked the whole tree, now let's build some data structures.

    # First lets create a report of the certs discovered
    report_filename = "crawler-" + str(datetime.now())
    with open(report_filename, "w") as report:
        for cert in processed_certs:
            pass
            # report.write(json.dumps(processed_certs[cert].en, indent=4))


if __name__ == "__main__":
    main()
