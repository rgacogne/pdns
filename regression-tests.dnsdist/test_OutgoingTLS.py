#!/usr/bin/env python
import dns
import requests
import ssl
import threading
import time

from dnsdisttests import DNSDistTest

class OutgoingTLSTests(object):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _verboseMode = True

    def checkOnlyTLSResponderHit(self, numberOfTLSQueries=1):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['TLS Responder'], numberOfTLSQueries)

    def getServerStat(self, key):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertTrue(len(content['servers']), 1)
        server = content['servers'][0]
        self.assertIn(key, server)
        return server[key]

    def testUDP(self):
        """
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        numberOfUDPQueries = 10
        for _ in range(numberOfUDPQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query
        numberOfQueries = numberOfUDPQueries + 1
        self.checkOnlyTLSResponderHit(numberOfUDPQueries)
        # our TLS responder does only one query per connection, so we need one for the TCP
        # query and one for the UDP one (the TCP test is done first)
        self.assertEqual(self.getServerStat('tcpNewConnections'), numberOfQueries)
        # we tried to reuse the connection (and then it failed but hey)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), numberOfQueries - 1)
        # we resumed the TLS session, though, but since we only learn about that
        # when the connection is closed, we are off by one
        self.assertEqual(self.getServerStat('tlsResumptions'), numberOfUDPQueries - 1)

    def testTCP(self):
        """
        Outgoing TLS: TCP query is sent via TLS
        """
        name = 'tcp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyTLSResponderHit()
        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), 0)
        self.assertEqual(self.getServerStat('tlsResumptions'), 0)

class BrokenOutgoingTLSTests(object):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'

    def checkNoResponderHit(self):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertNotIn('TLS Responder', self._responsesCounter)

    def testUDP(self):
        """
        Outgoing TLS (broken): UDP query is sent via TLS
        """
        name = 'udp.broken-outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        self.checkNoResponderHit()

    def testTCP(self):
        """
        Outgoing TLS (broken): TCP query is sent via TLS
        """
        name = 'tcp.broken-outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        self.checkNoResponderHit()

class TestOutgoingTLSOpenSSL(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10443
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLS(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10444
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        tlsContext.keylog_filename = "/tmp/keys"

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = 10445
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = 10446
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10447
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10448
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()
