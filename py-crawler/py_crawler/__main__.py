import logging
import os
from datetime import datetime
from importlib import resources
from pathlib import Path
from github import Github, Repository, ContentFile

from .certificate_graph import CertificateGraph
from .certs_to_p7b import P7C
from .graph_xml import GraphXML
from .gsa_certificate import GsaCertificate
from . import data


def main():
    # Identify and create output directories
    if "OUTPUT_DIR" in os.environ:
        output_path = Path(os.environ["OUTPUT_DIR"])
    else:
        output_path = Path.cwd().parent

    log_path = Path(output_path, "logs")
    report_path = Path(output_path, "reports")

    if not output_path.exists():
        Path.mkdir(output_path, parents=True)

    if not log_path.exists():
        Path.mkdir(log_path)

    if not report_path.exists():
        Path.mkdir(report_path)

    # Directory to pull the playbooks repo into
    if "PLAYBOOKS_DIR" in os.environ:
        playbooks_path = Path(os.environ["PLAYBOOKS_DIR"])
    else:
        playbooks_path = Path(Path.cwd().anchor, "playbooks")

    logger = logging.getLogger("py_crawler")
    logger.setLevel(logging.DEBUG)
    file_logger = logging.FileHandler(Path(log_path, "debug_log-" + str(datetime.now()) + ".log"))
    file_logger.setLevel(logging.DEBUG)
    logger.addHandler(file_logger)
    logger.debug("Starting Run and logging %s messages", file_logger.level)

    # Start with Common Policy Root
    common_file = resources.files(data).joinpath("fcpcag2.crt")

    with common_file.open(mode="rb") as common_file:
        common_bytes = common_file.read()

    anchor = GsaCertificate(input_bytes=common_bytes)

    # Create a graph
    common_graph = CertificateGraph(anchor=anchor)
    common_graph.build_graph()

    # First lets create a report of the certs discovered
    logger.info("Creating report for this crawler run.")
    report_filename = "crawler-" + str(datetime.now()) + ".json"
    with open(Path(report_path, report_filename), "w") as report:
        report.write(common_graph.report())

    # Next, produce a P7C
    logger.info("Creating P7B file")
    common_p7b = P7C(list(common_graph.edges.values()))

    with open("CACertificatesValidatingToFederalCommonPolicyG2.p7b", "wb") as common_p7b_file:
        common_p7b_file.write(common_p7b.get_p7b())

    # build the gexf output
    logger.info("building gexf")
    graph_xml = GraphXML(cert_graph=common_graph).tostring()
    if graph_xml is not None:
        with open(Path(output_path, "common_graph.gexf"), "w") as graph_file:
            # Write file
            graph_file.write(graph_xml)

    # Grab the playbooks repo from github
    github = Github()
    playbooks_repo = github.get_repo("Credentive-Sec/ficam-playbooks")
    contents = playbooks_repo.get_contents("")
    while type(contents) == list and contents:
        file_content = contents.pop(0)
        if file_content.type == "dir":
            contents.extend(playbooks_repo.get_contents(file_content.path))
        else:
            playbooks_repo.get_contents(file_content.path)


if __name__ == "__main__":
    main()
