from xml.etree import ElementTree
from datetime import date
from certificate_graph import CertificateGraph
from typing import Optional


class GraphXML:
    graph: ElementTree.ElementTree

    # Useful constants
    NODE_SIZE = "10.0"
    NODE_COLOR_R = "153"
    NODE_COLOR_G = "0"
    NODE_COLOR_B = "153"

    EDGE_COLOR_R = "153"
    EDGE_COLOR_G = "0"
    EDGE_COLOR_B = "153"

    XMLNS_DICT = {
        "xmlns": "http://www.gexf.net/1.2draft",
        "version": "1.2",
        "xmlns:viz": "http://www.gexf.net/1.2draft/viz",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:schemaLocation": "http://www.gexf.net/1.2draft http://www.gexf.net/1.2draft/gexf.xsd",
    }

    GEXF_TYPE = "directed"
    GEXF_MODE = "static"

    def __init__(self, cert_graph: CertificateGraph) -> None:
        root_element = ElementTree.Element("gexf", attrib=self.XMLNS_DICT)
        meta_element = ElementTree.SubElement(
            root_element,
            "meta",
            attrib={"lastmodifieddate": date.isoformat(date.today())},
        )
        creator_element = ElementTree.SubElement(meta_element, "creator")
        creator_element.text = "py-crawler"

        description_element = ElementTree.SubElement(meta_element, "description")

        graph_element = ElementTree.SubElement(
            root_element,
            "graph",
            attrib={"defaultedgetype": self.GEXF_TYPE, "mode": self.GEXF_MODE},
        )

        nodes_element = ElementTree.SubElement(graph_element, "nodes")

        for node in cert_graph.nodes:
            node_id = node
            # The label is the CN, which is everything after the first colon, but before the first comma
            node_label = (node.split(sep=":")[1]).split(",")[0]
            node_element = ElementTree.SubElement(
                nodes_element, "node", attrib={"id": node_id, "label": node_label}
            )
            node_attvalues = ElementTree.SubElement(node_element, "attvalues")
            node_size = ElementTree.SubElement(
                node_element, "viz:size", attrib={"value": self.NODE_SIZE}
            )
            node_color = ElementTree.SubElement(
                node_element,
                "viz:color",
                attrib={
                    "r": self.NODE_COLOR_R,
                    "g": self.NODE_COLOR_G,
                    "b": self.NODE_COLOR_B,
                },
            )

        edges_element = ElementTree.SubElement(graph_element, "edges")

        for edge_key in cert_graph.edges:
            edge_cert = cert_graph.edges[edge_key]
            edge_label = (edge_cert.subject.split(sep=":")[1]).split(",")[0]
            edge_element = ElementTree.SubElement(
                edges_element,
                "edge",
                attrib={
                    "id": edge_cert.subject,
                    "source": edge_cert.issuer,
                    "target": edge_cert.subject,
                    "label": edge_label,
                },
            )

            edge_color_element = ElementTree.SubElement(
                edge_element,
                "viz:color",
                attrib={
                    "r": self.NODE_COLOR_R,
                    "g": self.NODE_COLOR_G,
                    "b": self.NODE_COLOR_B,
                },
            )

            edge_attvalues_element = ElementTree.SubElement(edge_element, "attvalues")

        self.graph = ElementTree.ElementTree(root_element)

    def tostring(self) -> Optional[str]:
        return ElementTree.tostring(self.graph.getroot(), encoding="unicode")
