from scapy.layers.inet import traceroute, IP, TCP
from scapy.utils import wrpcap
from scapy.sendrecv import sr


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
        elif graph_type == "3d":
            self.result.trace3D()
        else:
            print("Unsupported graph type. Options include: graphviz and 3d.")

    def port_scan(self, port_list, type="syn-scan"):
        if type == "syn":
            self.result, unans = sr(IP(dst=self.targets)/TCP(flags="S", dport=port_list), timeout=1, retry=0)
            self.result.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",
                                prn=lambda s, r: r.sprintf("%IP.src% has %TCP.sport% open"))

    def write_pcap(self, file_out="out.pcap"):
        wrpcap(file_out, self.result)


def main():
    # The following is currently a Google Cloud Server ephemereal IP address range
    targets = ["35.238.223.0/24"]
    scapy = MyScapy(targets)
    scapy.port_scan(port_list=[22, 3389], type="syn")
    scapy.write_pcap()


if __name__ == '__main__':
    main()
