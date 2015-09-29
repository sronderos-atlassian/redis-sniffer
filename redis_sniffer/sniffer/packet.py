import itertools
import logging
import socket

import dpkt
import pcap

class RedisPacket():
    def __init__(self, ptime, size, client, is_request, data):
        self.ptime = ptime
        self.size = size
        self.client = client
        self.is_request = is_request
        self.data = data

class PacketFilter():
    def __init__(self, source, redis_port=6379, src_ip=None, dst_ip=None):
        self.redis_port = redis_port

        filter = 'tcp port %s' % redis_port
        if src_ip:
            filter += ' and src %s' % src_ip
        if dst_ip:
            filter += ' and dst %s' % dst_ip

        self.packets = pcap.pcap(source)
        self.packets.setfilter(filter)

    def __iter__(self):
        return itertools.imap(self._pc_to_redis_packet, self.packets)

    def _get_client(self, ip_pkt, tcp_pkt):
        src = socket.inet_ntoa(ip_pkt.src)
        sport = tcp_pkt.sport
        dst = socket.inet_ntoa(ip_pkt.dst)
        dport = tcp_pkt.dport
        src_addr = '%s:%s' % (src, sport)
        dst_addr = '%s:%s' % (dst, dport)
        if sport == self.redis_port:
            logging.debug("Data is a redis response")
            is_request = False
            client = dst_addr
        else:
            logging.debug("Data is a redis request")
            is_request = True
            client = src_addr
        return client, is_request

    def _pc_to_redis_packet(self, pcap):
        ptime, pdata = pcap
        ether_pkt = dpkt.ethernet.Ethernet(pdata)
        ip_pkt = ether_pkt.data
        tcp_pkt = ip_pkt.data
        tcp_data = tcp_pkt.data

        client, is_request = self._get_client(ip_pkt, tcp_pkt)

        return RedisPacket(ptime, len(pdata), client, is_request, tcp_data)
