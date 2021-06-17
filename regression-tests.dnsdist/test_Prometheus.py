#!/usr/bin/env python
import os
import requests
import subprocess
import unittest
from dnsdisttests import DNSDistTest

@unittest.skipIf('SKIP_PROMETHEUS_TESTS' in os.environ, 'Prometheus tests are disabled')
class TestPrometheus(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$argon2id$v=19$m=65536,t=2,p=1$mTJBHtI/KyO8oVDy8wyizg$8NK4ap5ohC7ylY8Dua61iBqhQw0cbcmXUaOpotC2hC0'
    _webServerAPIKey = 'apisecret'
    _config_params = ['_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKey']
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    def checkPrometheusContentBasic(self, content):
        for line in content.splitlines():
            if line.startswith('# HELP'):
                tokens = line.split(' ')
                self.assertGreaterEqual(len(tokens), 4)
            elif line.startswith('# TYPE'):
                tokens = line.split(' ')
                self.assertEqual(len(tokens), 4)
                self.assertIn(tokens[3], ['counter', 'gauge', 'histogram'])
            elif not line.startswith('#'):
                tokens = line.split(' ')
                self.assertEqual(len(tokens), 2)
                if not line.startswith('dnsdist_'):
                    raise AssertionError('Expecting prometheus metric to be prefixed by \'dnsdist_\', got: "%s"' % (line))

    def checkPrometheusContentPromtool(self, content):
        output = None
        try:
            testcmd = ['promtool', 'check', 'metrics']
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input=content)
        except subprocess.CalledProcessError as exc:
            raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, process.output))

        # commented out because promtool returns 3 because of the "_total" suffix warnings
        #if process.returncode != 0:
        #  raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, output))

        for line in output[0].splitlines():
            if line.endswith(b"should have \"_total\" suffix"):
                continue
            raise AssertionError('%s returned an unexpected output. Faulty line is "%s", complete content is "%s"' % (testcmd, line, output))

    def testMetrics(self):
        """
        Prometheus: Retrieve metrics
        """
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/metrics'
        r = requests.get(url, auth=('whatever', self._webServerBasicAuthPassword), timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.checkPrometheusContentBasic(r.text)
        self.checkPrometheusContentPromtool(r.content)
