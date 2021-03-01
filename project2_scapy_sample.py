from scapy.layers.inet import traceroute
from scapy.utils import wrpcap


class MyScapy:
    def __init__(self, targets):
        self.targets = targets

    def trace_route(self, graph_type, file_out=None):
        self.result, unans = traceroute(self.targets)
        if graph_type == "graphviz":
            if file_out:
                self.result.graph()
            else:
                self.result.graph(target=file_out)
        elif graph_type == "3D":
            self.result.trace3D()

    def write_pcap(self, file_out="out.pcap"):
        wrpcap(file_out, self.result)


def main():
    # Include your own list of websites to trace
    targets = ["www.ualr.edu", "www.google.com", "ok.ru", "fnb.co.za"]
    scapy = MyScapy(targets)
    scapy.trace_route("graphviz")
    scapy.write_pcap()


if __name__ == '__main__':
    main()

