from pyvis.network import Network

def build_attack_graph(detections):

    net = Network(
        height="500px",
        width="100%",
        bgcolor="#03090D",
        font_color="white"
    )

    previous = None

    for detection in detections:

        net.add_node(
            detection,
            label=detection
        )

        if previous:

            net.add_edge(previous, detection)

        previous = detection

    net.save_graph("attack_graph.html")

    return "attack_graph.html"