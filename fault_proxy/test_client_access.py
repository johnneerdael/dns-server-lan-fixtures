import os
import threading
import unittest
from unittest.mock import patch

from dns_fault_proxy import Config, _make_server, _TCPServer, _UDPServer, _TCPHandler, _UDPHandler


class ClientAccessTests(unittest.TestCase):
    def test_untrusted_clients_are_rejected_before_udp_and_tcp_handlers(self):
        with patch.dict(os.environ, {"LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0", "DNS_ALLOWED_CLIENTS": "192.0.2.0/24,2001:db8::/64"}, clear=True):
            # Let the OS choose the test socket port; environment ports remain validated.
            os.environ["LISTEN_PORT"] = "5301"
            config = Config.from_env()
        from dataclasses import replace
        config = replace(config, listen_port=0)
        for server_type, handler in [(_TCPServer, _TCPHandler), (_UDPServer, _UDPHandler)]:
            with self.subTest(transport=server_type.transport_name):
                server = _make_server(server_type, handler, config, threading.BoundedSemaphore(2))
                try:
                    self.assertFalse(server.verify_request(None, ("198.51.100.5", 4000)))
                    self.assertFalse(server.verify_request(None, ("2001:db9::1", 4000)))
                    self.assertTrue(server.verify_request(None, ("192.0.2.10", 4000)))
                    self.assertTrue(server.verify_request(None, ("::ffff:192.0.2.10", 4000)))
                    self.assertTrue(server.verify_request(None, ("2001:db8::1", 4000)))
                    self.assertTrue(server.verify_request(None, ("127.0.0.1", 4000)))
                finally:
                    server.server_close()

    def test_empty_invalid_and_unrestricted_networks_fail_at_startup(self):
        for value in ["", "192.0.2.0/24,", "any", "0.0.0.0/0", "::/0", "192.0.2.300/24"]:
            with self.subTest(value=value), patch.dict(os.environ, {"DNS_ALLOWED_CLIENTS": value}, clear=True):
                with self.assertRaisesRegex(SystemExit, "DNS_ALLOWED_CLIENTS"):
                    Config.from_env()


if __name__ == "__main__":
    unittest.main()
