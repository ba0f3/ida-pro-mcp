import unittest
from unittest import mock
import json
import threading
import time
from http.client import HTTPConnection, IncompleteRead
from urllib.error import URLError
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Mock IDA-specific modules
ida_modules = [
    "ida_hexrays", "ida_kernwin", "ida_funcs", "ida_gdl", "ida_lines",
    "ida_idaapi", "idc", "idaapi", "idautils", "ida_nalt", "ida_bytes",
    "ida_typeinf", "ida_xref", "ida_entry", "ida_idd", "ida_dbg",
    "ida_name", "ida_ida", "ida_frame"
]
for mod_name in ida_modules:
    sys.modules[mod_name] = mock.MagicMock()
sys.modules["idaapi"].get_kernel_version.return_value = "9.0"

from ida_pro_mcp.mcp_plugin import Server, JSONRPCRequestHandler, CustomThreadedHTTPServer, MCP_PROTOCOL_VERSION


class TestMCPServer(unittest.TestCase):
    server_thread = None
    server = None
    port = 13337
    host = "localhost"

    @classmethod
    def setUpClass(cls):
        # Start the server in a background thread
        cls.server = Server()
        cls.server.PORT = cls.port
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Give the server a moment to start

    @classmethod
    def tearDownClass(cls):
        # Stop the server
        if cls.server:
            cls.server.stop()
        if cls.server_thread:
            cls.server_thread.join()

    def test_cors_options_request(self):
        """Test that the server responds correctly to an OPTIONS pre-flight request."""
        conn = HTTPConnection(self.host, self.port)
        conn.request("OPTIONS", "/mcp")
        response = conn.getresponse()
        self.assertEqual(response.status, 204)
        self.assertIn("Access-Control-Allow-Origin", response.headers)
        self.assertIn("Access-Control-Allow-Methods", response.headers)
        self.assertIn("Access-Control-Allow-Headers", response.headers)
        conn.close()

    def test_initialize_method(self):
        """Test the 'initialize' JSON-RPC method."""
        conn = HTTPConnection(self.host, self.port)
        headers = {"Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": [],
            "id": 1
        }
        conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = json.loads(response.read().decode())
        self.assertEqual(data["id"], 1)
        self.assertIn("result", data)
        self.assertIn("capabilities", data["result"])
        conn.close()

    def test_session_management(self):
        """Test that the server correctly manages sessions."""
        # First request, should get a new session ID
        conn = HTTPConnection(self.host, self.port)
        headers = {"Content-Type": "application/json"}
        payload = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        session_id = response.getheader("Mcp-Session-Id")
        self.assertIsNotNone(session_id)
        conn.close()

        # Second request, should use the same session ID
        conn = HTTPConnection(self.host, self.port)
        headers["Mcp-Session-Id"] = session_id
        conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Mcp-Session-Id"), session_id)
        conn.close()

    def test_sse_broadcast(self):
        """Test that the server broadcasts messages to SSE clients."""
        # Connect an SSE client
        sse_conn = HTTPConnection(self.host, self.port)
        sse_conn.request("GET", "/mcp")
        sse_response = sse_conn.getresponse()
        self.assertEqual(sse_response.status, 200)

        # Make a POST request to trigger a broadcast
        post_conn = HTTPConnection(self.host, self.port)
        headers = {"Content-Type": "application/json"}
        payload = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        post_conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
        post_response = post_conn.getresponse()
        self.assertEqual(post_response.status, 200)
        post_conn.close()

        # Check if the SSE client received the broadcast
        try:
            # This will likely hang if no data is received, so we'll need a timeout
            line = sse_response.fp.readline()
            self.assertTrue(line.startswith(b"event: jsonrpc-request"))
        except (IncompleteRead, URLError) as e:
            self.fail(f"SSE connection failed: {e}")
        finally:
            sse_conn.close()


if __name__ == "__main__":
    unittest.main()