#!/usr/bin/env python
import dns
import json
import requests
import statistics
import time
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestSelfAnsweredPerformance(DNSDistTest):
    _webTimeout = 5.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohServerPort = pickAvailablePort()
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))

    _config_params = ['_tlsServerPort', '_serverCert', '_serverKey', '_dohServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    addDOH3Local("127.0.0.1:%d", "%s", "%s")

    setACL({"127.0.0.1/32", "::1/128"})

    newServer{address="127.0.0.1:%d"}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    addAction(QNameSuffixRule('self-answered.performance.test.powerdns.com.'), RCodeAction(DNSRCode.REFUSED))
    """

    def getLatencySeenByDNSdist(self, protocol='udp'):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        name = 'latency-avg100' if protocol == 'udp' else 'latency-' + protocol + '-avg100'
        for entry in content:
            if entry['name'] == name:
                return int(entry['value'])
        self.assertTrue(False)

    def getCPUSeenByDNSdist(self, kind='user'):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        name = 'cpu-' + kind + '-msec'
        for entry in content:
            if entry['name'] == name:
                return int(entry['value'])

    def getLatencyMetrics(self, latencies):
        latencies = sorted(latencies)
        count = len(latencies)
        maximum = 0
        for latency in latencies:
            if latency > maximum:
                maximum = latency
        results = { 'maximum': maximum}
        position = round(count * 95 / 100)
        results['95p'] = latencies[position - 1]
        position = round(count * 99 / 100)
        results['99p'] = latencies[position - 1]
        results['mean'] = statistics.mean(latencies)
        results['median'] = statistics.median(latencies)
        results['stdev'] = statistics.stdev(latencies)
        return results

    def checkLatencies(self, metrics, maximum, p95, p99):
        self.assertLessEqual(metrics['maximum'], maximum * 1000)
        self.assertLessEqual(metrics['95p'], p95 * 1000)
        self.assertLessEqual(metrics['99p'], p99 * 1000)

    def generateMetrics(self, protocol, query, response=None, useQueue=False):
        if protocol in ['dot', 'doh', 'doq', 'doh3']:
            method = 'send' + protocol.upper() + 'QueryWrapper'
        else:
            method = 'send' + protocol.upper() + 'Query'
        latencies = []
        userCPUBefore = self.getCPUSeenByDNSdist('user')
        systemCPUBefore = self.getCPUSeenByDNSdist('sys')
        for idx in range(100):
            sender = getattr(self, method)
            start = time.time_ns()
            (_, receivedResponse) = sender(query, response=response, useQueue=useQueue)
            end = time.time_ns()
            latencies.append(end - start)

        pyLatMetrics = self.getLatencyMetrics(latencies)
        # in microseconds
        #self.checkLatencies(pyLatMetrics, maximum=1000, p95=500, p99=800)
        internalLatency = self.getLatencySeenByDNSdist(protocol)
        internalUserCPU = self.getCPUSeenByDNSdist('user')
        internalSysCPU = self.getCPUSeenByDNSdist('sys')
        return {'internal-latency-µs': internalLatency,
                'internal-cpu-user': internalUserCPU,
                'internal-cpu-sys': internalSysCPU,
                'external-latencies-ns': pyLatMetrics}

    def testSelfAnswered(self):
        name = 'self-answered.performance.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        metrics = {}
        for protocol in ['udp', 'tcp', 'dot', 'doh', 'doq', 'doh3']:
            metrics[protocol] = self.generateMetrics(protocol, query)
        #print(json.dumps(metrics))
        path = 'dnsdist_self_answered.json'
        with open(path, 'w') as jfile:
            json.dump(metrics, jfile)

    def testCacheMiss(self):
        name = 'cache-miss.performance.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        metrics = {}
        for protocol in ['udp', 'tcp', 'dot', 'doh', 'doq', 'doh3']:
            metrics[protocol] = self.generateMetrics(protocol, query, response, True)
        path = 'dnsdist_cache_miss.json'
        with open(path, 'w') as jfile:
            json.dump(metrics, jfile)
