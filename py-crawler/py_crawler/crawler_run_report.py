from __future__ import annotations

import json
import logging
import datetime
from typing import Dict, List, Optional, Set, Tuple, Union

from .certificate_graph import CertificateGraph
from .gsa_certificate import GsaCertificate

logger = logging.getLogger("py_crawler.crawler_run_report")


class CrawlerRunReport:
    report = dict[str, Union[str, list[str], dict[str, str]]]

    def __init__(self, run_graph: CertificateGraph) -> None:
        self.report = {}
        self.report["anchor"] = run_graph.anchor.issuer
        self.report["changes"] = {}
        # new_certs has every cert that is less than two weeks old
        self.report["changes"]["new_certs"] = [
            identifier
            for identifier in run_graph.edges
            if datetime.datetime.now(tz=datetime.timezone.utc)
            - run_graph.edges[identifier].cert.not_valid_before
            < datetime.timedelta(weeks=2)
        ]
        self.report["issuers"] = []
        for node in run_graph.nodes:
            self.report["issuers"].append(node)
        self.report["valid-certs"] = []
        for cert in run_graph.edges.values():
            self.report["valid-certs"].append(cert.report_entry())
        self.report["bad-certs"] = []
        for cert in run_graph.no_path:
            self.report["bad-certs"].append(cert.report_entry())
        self.report["found-paths"] = []
        for path in run_graph.paths:
            self.report["found-paths"].append(run_graph.paths[path].description)

    def cert_report(self, cert: GsaCertificate) -> dict[str, str]:
        report_entry = {}
        report_entry["subject"] = cert.subject
        report_entry["issuer"] = cert.issuer
        report_entry["serial-number"] = cert.cert.serial_number
        if cert.cert.authority_key_identifier is not None:
            report_entry["akid"] = " ".join(
                "{:02x}".format(byte) for byte in cert.cert.authority_key_identifier
            )
        if cert.cert.key_identifier is not None:
            report_entry["skid"] = " ".join(
                "{:02x}".format(byte) for byte in cert.cert.key_identifier
            )
        report_entry["status"] = cert.status
        report_entry["pathbuilder-result"] = cert.pathbuilder_result
        if cert.status == cert.Status.VALID:
            if len(cert.path_to_anchor.certs) > 0:
                report_entry["path-to-common"] = []
                for cert in cert.path_to_anchor.certs:
                    report_entry["path-to-common"].append(cert.subject)

            report_entry["sia-entries"] = {}
            for result in cert.sia_results:
                report_entry["sia-entries"][result.url] = []
                for cert in result.certs:
                    report_entry["sia-entries"][result.url].append(cert.subject)

            report_entry["aia-entries"] = {}
            for result in cert.aia_results:
                report_entry["aia-entries"][result.url] = []
                for cert in result.certs:
                    report_entry["aia-entries"][result.url].append(cert.issuer)

        elif cert.status == cert.Status.INVALID:
            report_entry["parent_path_identifier"] = cert.path_parent_identifier
            report_entry["validity-dates"] = {
                "not-before": str(cert.cert.not_valid_before),
                "not-after": str(cert.cert.not_valid_after),
            }

        return report_entry

    def to_json(self) -> str:
        return json.dumps(self.report, indent=4)
