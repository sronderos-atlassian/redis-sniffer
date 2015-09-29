#!/usr/bin/env python

""" A redis query sniffer
"""

import logging
import re

import hiredis

from redis_sniffer.log import Log
from redis_sniffer.sniffer.packet import RedisPacket, PacketFilter

class Sniffer:
    def __init__(self, source):
        self.packet_iterator = source
        """:type : PacketFilter """

    @staticmethod
    def version():
        return 'v1.1.0'

    def sniff(self):
        sessions = {}

        logging.debug("<=============== Checking for Ethernet Packets ==============>")
        for redis_packet in self.packet_iterator:
            tcp_data = redis_packet.data

            logging.debug("Checking the length of the tcp packet")

            if len(tcp_data) == 0:
                logging.debug("TCP Packet is empty")
                logging.debug("extra bytes: %s", size)
                continue

            logging.debug("TCP Packet has data")
            logging.debug("Checking to see if the data is a request or response")
            client = redis_packet.client
            size = redis_packet.size

            if redis_packet.is_request:
                # TODO: why is this check here?
                if not tcp_data:
                    logging.debug("TCP Data is empty")
                    logging.debug("extra bytes: %s", size)
                    continue

                session = sessions.get(client, None)
                if not session:
                    logging.debug("Creating a new session for %s", client)
                    session = RedisSession()
                    sessions[client] = session

                if session.is_receiving() and session.commands:
                    yield redis_packet.ptime, client, session.request_size, session.response_size, ' / '.join(session.commands)
                    session.clear()

                session.process_request_packet(size, tcp_data)

            else:
                session = sessions.get(client)
                if not session:
                    logging.debug("No session for %s. Drop unknown response",client)
                    logging.debug("extra bytes: %s", size)
                    continue

                session.process_response_packet(size, tcp_data)

                if session.is_receiving() and len(session.commands) == session.responses:
                    yield redis_packet.ptime, client, session.request_size, session.response_size, ' / '.join(
                        session.commands)
                    session.clear()



class RedisSession():
    def __init__(self):
        self.req_reader = hiredis.Reader()
        self.req_reader.setmaxbuf(0)
        self.resp_reader = hiredis.Reader()
        self.resp_reader.setmaxbuf(0)

        self.commands = []
        self.responses = 0
        self.request_size = 0
        self.response_size = 0

    def is_receiving(self):
        return self.response_size > 0

    def is_complete(self):
        return self.responses > 0 and self.responses == len(self.commands)

    def process_request_packet(self, length, data):
        self.request_size += length
        self.req_reader.feed(data)

        try:
            command = self.req_reader.gets()
            # command will be False or an array of tokens that describe the command
            while command is not False:
                self.commands.append(' '.join(command))
                command = self.req_reader.gets()
        except hiredis.ProtocolError:
            logging.debug('Partial command')

    def process_response_packet(self, length, data):
        self.response_size += length
        self.resp_reader.feed(data)

        try:
            response = self.resp_reader.gets()
            while response is not False:
                self.responses += 1
                response = self.resp_reader.gets()
        except hiredis.ProtocolError:
            logging.debug('Partial response')

    def clear(self):
        self.commands = []
        self.responses = 0
        self.request_size = 0
        self.response_size = 0
