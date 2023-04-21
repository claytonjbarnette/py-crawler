from __future__ import annotations

import math

from datetime import date
from typing import Optional
from xml.etree import ElementTree

from .certificate_graph import CertificateGraph
from .gsa_certificate import GsaCertificate


class GraphXML:
    xml_graph: ElementTree.ElementTree
    cert_graph: CertificateGraph

    # Useful constants
    NODE_SIZE = "10.0"
    NODE_COLOR_R = "153"
    NODE_COLOR_G = "0"
    NODE_COLOR_B = "153"

    EDGE_COLOR_R = "153"
    EDGE_COLOR_G = "0"
    EDGE_COLOR_B = "153"

    XMLNS_DICT = {
        "xmlns": "http://gexf.net/1.3",
        "xmlns:viz": "http://gexf.net/1.3/viz",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:schemaLocation": "http://gexf.net/1.3 http://gexf.net/1.3/gexf.xsd",
        "version": "1.3",
    }

    GEXF_TYPE = "directed"
    GEXF_MODE = "static"

    def get_node_location(
        self, node: GsaCertificate, ring_id: int, ring_index: int, ring_size: int
    ) -> ElementTree.Element:
        x_location = y_location = 0

        if ring_index == 0 and ring_size == 0:
            # This is the center, leave the x and y location as is
            pass
        else:
            radius = 100 * ring_id
            angle = math.ceil((360 / ring_size) * ring_index)

            x_location = math.ceil(math.cos(angle))
            y_location = math.ceil(math.sin(angle))

        return ElementTree.Element(
            "position",
            attrib={
                "x": str(x_location),
                "y": str(y_location),
                "z": "0",
            },
        )

    def write_node(self, node: GsaCertificate, node_names: list[str]) -> ElementTree.Element:
        node_id = node.subject
        # The label is the CN, which is everything after the first colon, but before the first comma
        node_label = (node.subject.split(sep=":")[1]).split(",")[0]
        node_element = ElementTree.Element("node", attrib={"id": node_id, "label": node_label})
        node_element.append(ElementTree.Element("size", attrib={"value": self.NODE_SIZE}))
        node_element.append(
            ElementTree.Element(
                "color",
                attrib={
                    "r": self.NODE_COLOR_R,
                    "g": self.NODE_COLOR_G,
                    "b": self.NODE_COLOR_B,
                },
            )
        )

        if len(node.sia_results) > 0:
            sub_nodes_element = ElementTree.SubElement(node_element, "nodes")
            for sia_result in node.sia_results:
                for cert in sia_result.certs:
                    if cert.subject not in node_names:
                        node_names.append(cert.subject)  # Track these to avoid duplicates
                        sub_nodes_element.append(self.write_node(cert, node_names=node_names))

        return node_element

    def __init__(self, cert_graph: CertificateGraph) -> None:
        self.cert_graph = cert_graph
        # Root
        root_element = ElementTree.Element("gexf", attrib=self.XMLNS_DICT)

        # Metadata
        meta_element = ElementTree.Element(
            "meta",
            attrib={"lastmodifieddate": date.isoformat(date.today())},
        )

        # Creator
        creator_element = ElementTree.Element("creator")
        creator_element.text = "py-crawler"
        meta_element.append(creator_element)

        # Description
        description_element = ElementTree.Element("description")
        description_element.text = f"Created by Py-Crawler on {date.today().isoformat()}"
        meta_element.append(description_element)

        # Attach completed metadata to root
        root_element.append(meta_element)

        # Create the Graph element under the root
        graph_element = ElementTree.Element(
            "graph",
            attrib={"defaultedgetype": self.GEXF_TYPE, "mode": self.GEXF_MODE},
        )

        # Create the nodes
        nodes_element = ElementTree.Element("nodes")
        nodes_element.append(self.write_node(self.cert_graph.anchor, node_names=[]))

        # Add the nodes to the graph
        graph_element.append(nodes_element)

        # Create the edges
        edges_element = ElementTree.Element("edges")

        edge_set: set[tuple[str, str]] = set()
        edges_dict: dict[str, dict[str, str]] = {}
        for edge_key in cert_graph.edges:
            edge_cert = cert_graph.edges[edge_key]
            edge_label = (edge_cert.subject.split(sep=":")[1]).split(",")[0]
            if (edge_cert.issuer, edge_cert.subject) not in edge_set:
                edges_dict[edge_label] = {
                    "id": edge_cert.subject,
                    "source": edge_cert.issuer,
                    "target": edge_cert.subject,
                    "label": edge_label,
                    "weight": "1.0",
                }
            else:
                edges_dict[edge_label]["weight"] = str(
                    float(edges_dict[edge_label]["weight"]) + 1.0
                )

        for label in edges_dict:
            edge_element = ElementTree.SubElement(
                edges_element,
                "edge",
                attrib=edges_dict[label],
            )

            edge_element.append(
                ElementTree.Element(
                    "color",
                    attrib={
                        "r": self.NODE_COLOR_R,
                        "g": self.NODE_COLOR_G,
                        "b": self.NODE_COLOR_B,
                    },
                )
            )

        # Add the edges to the graph
        graph_element.append(edges_element)

        # Add the graph to the root
        root_element.append(graph_element)

        self.xml_graph = ElementTree.ElementTree(root_element)

    def tostring(self) -> Optional[str]:
        return ElementTree.tostring(self.xml_graph.getroot(), encoding="unicode")
