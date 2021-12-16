#!/usr/bin/env python

import os
import socket
import threading
import unittest
import dns
from dnsdisttests import DNSDistTest

def AsyncResponder(listenPath, responsePath):
    # Make sure the socket does not already exist
    try:
        os.unlink(listenPath)
    except OSError:
        if os.path.exists(listenPath):
            raise

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(listenPath)
    except socket.error as e:
        print("Error binding in the Asynchronous responder: %s" % str(e))
        sys.exit(1)

    while True:
        data, addr = sock.recvfrom(65535)
        print("Got message [%d] '%s' from %s" % (len(data), data, addr)) 
        if not data:
            break

        request = dns.message.from_wire(data)
        reply = str(request.id) + ' '
        print(request.question[0].name)
        print(str(request.question[0].name))
        if str(request.question[0].name).startswith('allowed'):
            reply = reply + 'accept'
        elif str(request.question[0].name).startswith('refuse'):
            reply = reply + 'refuse'
        elif str(request.question[0].name).startswith('drop'):
            reply = reply + 'drop'
        elif str(request.question[0].name).startswith('custom'):
            reply = reply + 'custom'
        else:
            reply = reply + 'invalid'

        remote = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        remote.connect(responsePath)
        remote.send(reply.encode())
        print("Sent [%d] '%s' to %s" % (len(reply), reply, responsePath))

    sock.close()

asyncResponderSocketPath = '/tmp/async-responder.sock'
dnsdistSocketPath = '/tmp/dnsdist.sock'
asyncResponder = threading.Thread(name='Asynchronous Responder', target=AsyncResponder, args=[asyncResponderSocketPath, dnsdistSocketPath])
asyncResponder.setDaemon(True)
asyncResponder.start()

class TestAsync(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}

    local ffi = require("ffi")
    local C = ffi.C

    local filteringTagName = 'filtering'
    local filteringTagValue = 'pass'
    local asyncID = 0

    function gotAsyncResponse(endpointID, message, from)

      print('Got async response '..message)
      local parts = {}
      for part in message:gmatch("%%S+") do table.insert(parts, part) end
      if #parts ~= 2 then
        print('Invalid message')
        return
      end
      local queryID = tonumber(parts[1])
      if parts[2] == 'accept' then
        print('accepting')
        C.dnsdist_ffi_resume_from_async(asyncID, queryID, filteringTagName, #filteringTagName, filteringTagValue, #filteringTagValue)
        return
      end
      if parts[2] == 'refuse' then
        print('refusing')
        C.dnsdist_ffi_set_rcode_from_async(asyncID, queryID, DNSRCode.REFUSED, true)
        return
      end
      if parts[2] == 'drop' then
        print('dropping')
        C.dnsdist_ffi_drop_from_async(asyncID, queryID)
        return
      end
      if parts[2] == 'custom' then
        print('sending a custom response')
        local raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\004free\\002fr\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        C.dnsdist_ffi_set_answer_from_async(asyncID, queryID, raw, #raw)
        return
      end
    end

    local asyncResponderEndpoint = newNetworkEndpoint('%s')
    local listener = newNetworkListener()
    listener:addUnixListeningEndpoint('%s', 0, gotAsyncResponse)
    listener:start()

    function passQueryToAsyncFilter(dq)
      print('in passQueryToAsyncFilter')
      local timeout = 2000 -- 2000 ms

      local queryPtr = C.dnsdist_ffi_dnsquestion_get_header(dq)
      local querySize = C.dnsdist_ffi_dnsquestion_get_len(dq)

      print(C.dnsdist_ffi_dnsquestion_set_async(dq, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dq), timeout))
      asyncResponderEndpoint:send(ffi.string(queryPtr, querySize))

      return DNSAction.Allow
    end

    function passResponseToAsyncFilter(dr)
      print('in passResponseToAsyncFilter')
      local timeout = 2000 -- 2000 ms

      local responsePtr = C.dnsdist_ffi_dnsquestion_get_header(dr)
      local responseSize = C.dnsdist_ffi_dnsquestion_get_len(dr)

      print(C.dnsdist_ffi_dnsresponse_set_async(dr, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dr), timeout))
      asyncResponderEndpoint:send(ffi.string(responsePtr, responseSize))

      return DNSResponseAction.Allow
    end

    addAction(AllRule(), LuaFFIAction(passQueryToAsyncFilter))
    addResponseAction(AllRule(), LuaFFIResponseAction(passResponseToAsyncFilter))
    """
    _asyncResponderSocketPath = asyncResponderSocketPath
    _dnsdistSocketPath = dnsdistSocketPath
    _config_params = ['_testServerPort', '_asyncResponderSocketPath', '_dnsdistSocketPath']
    _verboseMode = True

    def testPass(self):
        """
        Async: Allowed
        """
        name = 'allowed.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testRefused(self):
        """
        Async: Refused
        """
        name = 'refused.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            print(expectedResponse)
            print(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

