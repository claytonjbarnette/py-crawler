from __future__ import annotations

import math
import logging

from datetime import date
from typing import Optional
from xml.etree import ElementTree
from xml.dom import minidom

from .certificate_graph import CertificateGraph
from .gsa_certificate import GsaCertificate

logger = logging.getLogger("py_crawler.graph_xml")


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

    def get_node_location(self, ring_id: int, ring_index: int, ring_size: int) -> tuple[int, int]:
        x_location = y_location = 0

        logger.debug(
            "Calling get_node_location with ring_id %s, ring_index %s, and ring_size %s",
            ring_id,
            ring_index,
            ring_size,
        )
        if ring_index == 0 and ring_size == 0:
            pass
        else:
            radius = 100 * ring_id
            radians = ((2 * math.pi) / ring_size) * ring_index

            x_location = math.ceil(radius * math.cos(radians))
            y_location = math.ceil(radius * math.sin(radians))

            logger.debug(
                "Node Location information - radius: %s, radians: %s, x_location: %s, y_location: %s",
                radius,
                radians,
                x_location,
                y_location,
            )

        return (x_location, y_location)

    def write_node(
        self,
        node: GsaCertificate,
        ring_tracker: dict[int, int],
        node_names: list[str],
    ) -> list[ElementTree.Element]:
        node_list = []
        node_geometry_dict: dict[str, str] = {}

        # The label is the CN, which is everything after the first colon, but before the first comma
        node_id = node.subject
        node_names.append(node_id)
        node_label = (node.subject.split(sep=":")[1]).split(",")[0]
        node_element = ElementTree.Element("node", attrib={"id": node_id, "label": node_label})
        node_element.append(ElementTree.Element("size", attrib={"value": self.NODE_SIZE}))
        node_element.append(
            ElementTree.Element(
                "viz:color",
                attrib={
                    "r": self.NODE_COLOR_R,
                    "g": self.NODE_COLOR_G,
                    "b": self.NODE_COLOR_B,
                },
            )
        )

        # Set up position
        if node.path_to_anchor is not None:
            ring_id = len(node.path_to_anchor.certs)
        else:
            ring_id = 0
        
        ring_size = self.cert_graph.ring_geometry[ring_id]
        (x_location, y_location) = self.get_node_location(
            ring_id=ring_id,
            ring_index=ring_tracker[ring_id],
            ring_size=ring_size,
        )
        ring_tracker[ring_id] += 1

        node_geometry_dict = {"x": str(x_location) + ".0", "y": str(y_location) + ".0", "z": "0.0"}

        node_element.append(ElementTree.Element("viz:position", attrib=node_geometry_dict))

        node_list.append(node_element)

        if len(node.sia_results) > 0:
            for sia_result in node.sia_results:
                for cert in sia_result.certs:
                    if cert.subject not in node_names:
                        node_names.append(cert.subject)  # Track these to avoid duplicates
                        node_list.extend(
                            self.write_node(
                                cert,
                                ring_tracker=ring_tracker,
                                node_names=node_names,
                            )
                        )

        return node_list

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

        # Initialize a dict to track the geometry for the node rings
        ring_tracker = {x: 0 for x in self.cert_graph.ring_geometry.keys()}

        nodes_element.extend(self.write_node(self.cert_graph.anchor, ring_tracker, node_names=[]))

        # Add the nodes to the graph
        graph_element.append(nodes_element)

        # Create the edges
        edges_element = ElementTree.Element("edges")
        edge_set: set[tuple[str, str]] = set()
        edges_dict: dict[str, dict[str, str]] = {}

        # Get all the certs that are not self-signed
        edge_certs = [cert for cert in cert_graph.edges.values() if cert.subject != cert.issuer]

        for edge_cert in edge_certs:
            edge_label = (edge_cert.subject.split(sep=":")[1]).split(",")[0]

            if (
                edge_cert.issuer != edge_cert.subject
                and (edge_cert.issuer, edge_cert.subject) not in edge_set
            ):
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
                    "viz:color",
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
        return minidom.parseString(ElementTree.tostring(self.xml_graph.getroot(), encoding="unicode")).toprettyxml(indent="    ")
