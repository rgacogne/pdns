import json
import os
import requests
import socket
import struct
import sys
import threading
import time

import dns
import dns.zone

from ixfrdisttests import IXFRDistTest

zones = {
    1: """
$ORIGIN example.
@        86400   SOA    foo bar 1 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
""",
    2: """
$ORIGIN example.
@        86400   SOA    foo bar 2 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
example.        8484    A       192.0.2.42
"""
}

class AXFRServer(object):

    def __init__(self, port):
        self._currentSerial = 0
        self._serverPort = port
        listener = threading.Thread(name='AXFR Listener', target=self._listener, args=[])
        listener.setDaemon(True)
        listener.start()

    def _getRecordsForSerial(self, serial):
        global zones
        return dns.zone.from_text(zones[serial])

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        print("current serial is %d, moving to %d" % (self._currentSerial, newSerial))
        if newSerial == self._currentSerial:
            return False

        if newSerial != self._currentSerial + 1:
            raise AssertionError("Asking the AXFR server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))

        global zones
        if newSerial not in zones:
            raise AssertionError("Asking the AXFR server to serve serial %d, but we don't have a corresponding zone" % (newSerial))

        self._currentSerial = newSerial
        return True

    def _getAnswer(self, message):

        response = dns.message.make_response(message)
        records = []

        if message.question[0].rdtype == dns.rdatatype.AXFR:
            records = self._getRecordsForSerial(self._currentSerial)

        response.answer = records
        return (self._currentSerial, response)

    def _connectionHandler(self, conn):
        data = None
        while True:
            data = conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = conn.recv(datalen)
            if not data:
                break

            message = dns.message.from_wire(data)
            if len(message.question) != 1:
                print('Invalid AXFR query, qdcount is %d' % (len(message.question)))
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid AXFR query, qtype is %d' % (message.question.rdtype))
                break
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype))
                break

            wire = answer.to_wire()
            conn.send(struct.pack("!H", len(wire)))
            conn.send(wire)
            self._currentSerial = serial
            break

        conn.close()

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the AXFR listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            try:
                (conn, _) = sock.accept()
                thread = threading.Thread(name='AXFR Connection Handler',
                                      target=self._connectionHandler,
                                      args=[conn])
                thread.setDaemon(True)
                thread.start()

            except socket.error as e:
                print('Error in AXFR socket: %s' % str(e))
                sock.close()

xfrServerPort = 4244
xfrServer = AXFRServer(xfrServerPort)

class IXFRDistBasicTest(IXFRDistTest):
    """
    This test makes sure that we correctly fetch a zone via AXFR, and provide the full AXFR and IXFR
    """

    global xfrServerPort
    _xfrDone = 0
    _config_domains = { 'example.com': '127.0.0.1:' + str(xfrServerPort) }

    @classmethod
    def setUpClass(cls):

        cls.startIXFRDist()
        cls.setUpSockets()

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=5):
        global xfrServer

        xfrServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            currentSerial = xfrServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                self._xfrDone = self._xfrDone + 1
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def checkFullZone(self, serial):
        global zones
        fullZone = dns.zone.from_text(zones[serial])
        expected = list(fullZone.iterate_rdatas())
        expected.sort()

        query = dns.message.make_query('example.com.', 'AXFR', want_dnssec=True)
        res = self.sendTCPQuery(query)
        print(res)

        self.assertEqual(res.answer, expected)

    def testXFR(self):
        # first zone, only a should be blocked
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkFullZone(1)
