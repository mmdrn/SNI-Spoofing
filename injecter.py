import socket
import sys
from abc import ABC, abstractmethod

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


class TcpInjector(ABC):
    def __init__(self, queue_num: int = 0):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    @abstractmethod
    def inject(self, scapy_pkt, nfq_pkt):
        sys.exit("Not implemented")

    def send_raw(self, scapy_pkt):
        self.raw_sock.sendto(bytes(scapy_pkt), (scapy_pkt[IP].dst, 0))

    def _callback(self, nfq_pkt):
        scapy_pkt = IP(nfq_pkt.get_payload())
        self.inject(scapy_pkt, nfq_pkt)

    def run(self):
        self.nfqueue.bind(self.queue_num, self._callback)
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.nfqueue.unbind()
            self.raw_sock.close()
