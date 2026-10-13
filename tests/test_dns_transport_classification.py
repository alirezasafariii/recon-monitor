import socket
import unittest
from unittest.mock import patch
import safe_transport as transport

class Policy:
    def url_in_scope(self,url):return True

class DNSClassification(unittest.TestCase):
    def test_lookup_failure_is_not_evidence_of_private_address(self):
        with patch.object(transport.socket,'getaddrinfo',side_effect=socket.gaierror(-2,'unavailable')),patch.object(transport,'build_pinned_opener') as opener:
            result=transport.perform_pinned_download('https://a.example.test/app.js',Policy(),max_response_bytes=1000)
        self.assertEqual(result['error'],'dns_resolution_failed')
        self.assertEqual(result['transport_status'],'error')
        self.assertEqual(result['resolved_addresses'],[])
        opener.assert_not_called()

    def test_private_and_mixed_addresses_remain_blocked(self):
        for addresses in [['127.0.0.1'],['1.1.1.1','10.0.0.1']]:
            with patch.object(transport,'resolve_public_addresses',return_value=(False,addresses)),patch.object(transport,'build_pinned_opener') as opener:
                result=transport.perform_pinned_download('https://a.example.test/app.js',Policy(),max_response_bytes=1000)
            self.assertEqual(result['error'],'non_public_resolution_blocked')
            self.assertEqual(result['transport_status'],'stopped_for_safety')
            opener.assert_not_called()

    def test_request_and_tls_peer_expose_resolution_failure(self):
        with patch.object(transport,'resolve_public_addresses',return_value=(False,[])),patch.object(transport,'build_pinned_opener') as opener:
            result,status=transport.perform_pinned_request({'url':'https://a.example.test/'},Policy(),safe_methods={'GET'},url_safety=lambda *a:(True,''),observation=lambda method,url,code,headers,body,error:{'error':error},max_response_bytes=1000,validation_version='test')
            tls=transport.fetch_pinned_tls_peer('https://a.example.test/',Policy())
        self.assertEqual(result['error'],'dns_resolution_failed')
        self.assertEqual(status,'error')
        self.assertEqual(tls['error'],'dns_resolution_failed')
        opener.assert_not_called()

if __name__=='__main__':unittest.main()
