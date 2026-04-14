import asyncio
import socket
import sys
import threading
import time

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send as scapy_send

from monitor_connection import MonitorConnection
from injecter import TcpInjector


def get_tcp_payload(pkt):
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    return b""


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):

    def __init__(self, interface_ip: str, connect_ip: str,
                 connections: dict[tuple, FakeInjectiveConnection], queue_num: int = 0):
        super().__init__(queue_num)
        self.interface_ip = interface_ip
        self.connect_ip = connect_ip
        self.connections = connections

    def fake_send_thread(self, connection: FakeInjectiveConnection):
        time.sleep(0.001)
        with connection.thread_lock:
            if not connection.monitor:
                return

            if connection.bypass_method == "wrong_seq":
                fake_pkt = IP(src=connection.src_ip, dst=connection.dst_ip) / \
                           TCP(sport=connection.src_port, dport=connection.dst_port,
                               seq=(connection.syn_seq + 1 - len(connection.fake_data)) & 0xffffffff,
                               ack=(connection.syn_ack_seq + 1) & 0xffffffff,
                               flags='PA') / \
                           Raw(load=connection.fake_data)
                connection.fake_sent = True
                scapy_send(fake_pkt, verbose=False)
            else:
                sys.exit("not implemented method!")

    def on_unexpected_packet(self, pkt, nfq_pkt, connection: FakeInjectiveConnection, info_m: str):
        print(info_m, pkt.summary())
        connection.sock.close()
        connection.peer_sock.close()
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        nfq_pkt.accept()

    def on_inbound_packet(self, pkt, nfq_pkt, connection: FakeInjectiveConnection):
        tcp = pkt[TCP]
        payload = get_tcp_payload(pkt)

        if connection.syn_seq == -1:
            self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected inbound packet, no syn sent!")
            return
        if tcp.flags.A and tcp.flags.S and (not tcp.flags.R) and (not tcp.flags.F) and (
                len(payload) == 0):
            seq_num = tcp.seq
            ack_num = tcp.ack
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected inbound syn-ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(connection.syn_seq))
                return
            connection.syn_ack_seq = seq_num
            nfq_pkt.accept()
            return
        if tcp.flags.A and (not tcp.flags.S) and (not tcp.flags.R) and (
                not tcp.flags.F) and (len(payload) == 0) and connection.fake_sent:
            seq_num = tcp.seq
            ack_num = tcp.ack
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                              connection.syn_seq))
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            nfq_pkt.accept()
            return
        self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, pkt, nfq_pkt, connection: FakeInjectiveConnection):
        tcp = pkt[TCP]
        payload = get_tcp_payload(pkt)

        if connection.sch_fake_sent:
            self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
        if tcp.flags.S and (not tcp.flags.A) and (not tcp.flags.R) and (not tcp.flags.F) and (
                len(payload) == 0):
            seq_num = tcp.seq
            ack_num = tcp.ack
            if ack_num != 0:
                self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected outbound syn packet, seq not matched! " + str(
                    seq_num) + " " + str(connection.syn_seq))
                return
            connection.syn_seq = seq_num
            nfq_pkt.accept()
            return
        if tcp.flags.A and (not tcp.flags.S) and (not tcp.flags.R) and (not tcp.flags.F) and (
                len(payload) == 0):
            seq_num = tcp.seq
            ack_num = tcp.ack
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected outbound ack packet, seq not matched! " + str(
                                              seq_num) + " " + str(
                                              connection.syn_seq))
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(pkt, nfq_pkt, connection,
                                          "unexpected outbound ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(
                                              connection.syn_ack_seq))
                return

            nfq_pkt.accept()
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(connection,), daemon=True).start()
            return
        self.on_unexpected_packet(pkt, nfq_pkt, connection, "unexpected outbound packet")
        return

    def inject(self, scapy_pkt, nfq_pkt):
        ip = scapy_pkt[IP]
        tcp = scapy_pkt[TCP]

        if ip.src == self.connect_ip:
            # Inbound packet (from server)
            c_id = (ip.dst, tcp.dport, ip.src, tcp.sport)
            try:
                connection = self.connections[c_id]
            except KeyError:
                nfq_pkt.accept()
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        nfq_pkt.accept()
                        return
                    self.on_inbound_packet(scapy_pkt, nfq_pkt, connection)
        elif ip.dst == self.connect_ip:
            # Outbound packet (to server)
            c_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            try:
                connection = self.connections[c_id]
            except KeyError:
                nfq_pkt.accept()
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        nfq_pkt.accept()
                        return
                    self.on_outbound_packet(scapy_pkt, nfq_pkt, connection)
        else:
            nfq_pkt.accept()
