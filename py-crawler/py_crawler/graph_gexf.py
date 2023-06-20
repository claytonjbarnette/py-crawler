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


class GraphGexf:
    # An object to store the GEXF contents
    xml_graph: ElementTree.ElementTree
    cert_graph: CertificateGraph

    # To layout the graph using the current library, we will need to identify
    # the number of concentric rings and the number of elements per ring.
    # We define a where the key is the ring id and the value is the number of elements.
    ring_geometry: dict[int, int] = {}

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

        ring_size = self.ring_geometry[ring_id]
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

    def calculate_ring_geometry(self, certs: list[GsaCertificate]) -> None:
        # Calculate ring geometry, the number of rings (with anchor at the center) and the number
        # of points in each ring

        # Start with the center
        self.ring_geometry[0] = 1

        for cert in certs:
            cert_ring = len(cert.path_to_anchor.certs)
            # Add 1 more point to the corresponding ring. If the key doesn't exist, create
            # it with a value of 1
            try:
                logger.debug("Adding 1 to ring[%s]", cert_ring)
                self.ring_geometry[cert_ring] += 1
            except KeyError:
                logger.debug("Initializing ring[%s] with value 1", cert_ring)
                self.ring_geometry[cert_ring] = 1

    def __init__(self, cert_graph: CertificateGraph) -> None:
        self.cert_graph = cert_graph

        # Get all the certs that are not self-signed
        edge_certs = [cert for cert in cert_graph.edges.values() if cert.subject != cert.issuer]

        # Get rid of redundant certs by turning the list into a set
        edge_cert_set: set[tuple[str, str, GsaCertificate]] = set(
            [(cert.issuer, cert.subject, cert) for cert in edge_certs]
        )

        # Build the Ring Geometry
        self.calculate_ring_geometry(certs=[cert[2] for cert in edge_cert_set])

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
        ring_tracker = {x: 0 for x in self.ring_geometry.keys()}

        nodes_element.extend(self.write_node(self.cert_graph.anchor, ring_tracker, node_names=[]))

        # Add the nodes to the graph
        graph_element.append(nodes_element)

        # Create the edges
        edges_element = ElementTree.Element("edges")
        edges_dict: dict[str, dict[str, str]] = {}

        for edge_cert in [cert[2] for cert in edge_cert_set]:
            edge_label = (edge_cert.subject.split(sep=":")[1]).split(",")[0]

            edges_dict[edge_label] = {
                "id": edge_cert.subject,
                "source": edge_cert.issuer,
                "target": edge_cert.subject,
                "label": edge_label,
                "weight": "1.0",
            }

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
        return minidom.parseString(
            ElementTree.tostring(self.xml_graph.getroot(), encoding="unicode")
        ).toprettyxml(indent="    ")
