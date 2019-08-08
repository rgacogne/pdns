#!/usr/bin/env python
import dns
import subprocess
from dnsdisttests import DNSDistTest

class DNSDistOCSPTest(DNSDistTest):

    @classmethod
    def checkOCSPStatus(cls, addr, port, serverName, caFile):
        testcmd = ['openssl', 's_client', '-CAfile', caFile, '-connect', '%s:%d' % (addr, port), '-status', '-servername', serverName ]
        output = None
        try:
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input='')
        except subprocess.CalledProcessError as exc:
            raise AssertionError('dnsdist --check-config failed (%d): %s' % (exc.returncode, exc.output))

        return output[0].decode()

class TestOCSPDOH(DNSDistOCSPTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _dohServerPort = 8443
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, { ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_dohServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testOCSP(self):
        """
        OCSP: DOH
        """
        output = self.checkOCSPStatus('127.0.0.1', self._dohServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)

class TestOCSPTLSGnuTLS(DNSDistOCSPTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _tlsServerPort = 8443
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="gnutls", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testOCSP(self):
        """
        OCSP: TLS (GnuTLS)
        """
        output = self.checkOCSPStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)

class TestOCSPTLSOpenSSL(DNSDistOCSPTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _tlsServerPort = 8443
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testOCSP(self):
        """
        OCSP: TLS (OpenSSL)
        """
        output = self.checkOCSPStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)
