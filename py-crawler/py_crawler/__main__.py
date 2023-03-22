from importlib import resources
from gsa_cert import GsaCert
import logging


def main():
    # Configure Logging
    logger = logging.getLogger("py_crawler")
    logger.setLevel(logging.DEBUG)
    console_logger = logging.StreamHandler()
    console_logger.setLevel(logging.DEBUG)
    logger.addHandler(console_logger)
    logger.debug("logging DEBUG messages")

    # Start with Common
    common_file = resources.files("resources").joinpath("fcpcag2.crt")

    with common_file.open(mode="rb") as common_file:
        common_bytes = common_file.read()

    common_cert = GsaCert(common_bytes)

    common_cert.sia_certs()


if __name__ == "__main__":
    main()
