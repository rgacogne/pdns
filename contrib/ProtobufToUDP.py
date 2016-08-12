#!/usr/bin/env python2

import socket
import struct
import sys
import threading

import dns
import clientsubnetoption

# run: protoc -I=../pdns/ --python_out=. ../pdns/dnsmessage.proto
# to generate dnsmessage_pb2
import dnsmessage_pb2

class PDNSPBConnHandler(object):

    def __init__(self, conn, destfamily, desttype, destaddr):
        self._conn = conn
        self._dest = socket.socket(destfamily, desttype)
        try:
            self._dest.connect(destaddr)
        except socket.error as exp:
            print("Error while connecting outgoing socket: %s" % str(exp))
            sys.exit(1)

    def run(self):
        while True:
            data = self._conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = self._conn.recv(datalen)

            msg = dnsmessage_pb2.PBDNSMessage()
            msg.ParseFromString(data)
            if msg.type == dnsmessage_pb2.PBDNSMessage.DNSQueryType:
                query = self.queryFromPB(msg)
                if query:
                    self.sendQuery(query.to_wire())

        self._conn.close()

    def sendQuery(self, query):
        self._dest.send(query)

    def queryFromPB(self, message):
        if not message.id:
            return None

        if not message.HasField('question'):
            return None

        if message.socketProtocol != dnsmessage_pb2.PBDNSMessage.UDP:
            return  None

        qname = message.question.qName
        qtype = message.question.qType
        qclass = 1
        if message.question.HasField('qClass'):
            qclass = message.question.qClass

        ecso = None
        fromvalue = getattr(message, 'from')
        if message.socketFamily == dnsmessage_pb2.PBDNSMessage.INET:
            if message.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET, fromvalue)
                ecso = clientsubnetoption.ClientSubnetOption(ipfromstr, 32)
        else:
            if message.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET6, fromvalue)
                ecso = clientsubnetoption.ClientSubnetOption(ipfromstr, 128)

        if not ecso:
            return None

        return dns.message.make_query(qname, qtype, qclass, use_edns=True, options=[ecso])

class PDNSPBToUDPListener(object):

    def __init__(self, addr, port, destaddr, destport):
        res = socket.getaddrinfo(addr, port, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM, 0,
                                 socket.AI_PASSIVE)
        if len(res) != 1:
            print("Error parsing the supplied address")
            sys.exit(1)
        family, socktype, _, _, sockaddr = res[0]
        self._sock = socket.socket(family, socktype)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            self._sock.bind(sockaddr)
        except socket.error as exp:
            print("Error while binding: %s" % str(exp))
            sys.exit(1)

        res = socket.getaddrinfo(destaddr, destport, socket.AF_UNSPEC,
                                 socket.SOCK_DGRAM, 0,
                                 socket.AI_PASSIVE)
        if len(res) != 1:
            print("Error parsing the supplied out address")
            sys.exit(1)
        self._destfamily, self._desttype, _, _, self._destaddr = res[0]

        self._sock.listen(100)

    def run(self):
        while True:
            (conn, _) = self._sock.accept()

            handler = PDNSPBConnHandler(conn,
                                        self._destfamily,
                                        self._desttype,
                                        self._destaddr)
            thread = threading.Thread(name='Connection Handler',
                                      target=PDNSPBConnHandler.run,
                                      args=[handler])
            thread.setDaemon(True)
            thread.start()

        self._sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit('Usage: %s <incoming address> <incoming port> <outgoing address> <outgoing port>' % (sys.argv[0]))

    PDNSPBToUDPListener(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]).run()
    sys.exit(0)
