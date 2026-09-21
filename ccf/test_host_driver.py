import importlib.util
import pathlib
import socket
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("host_driver", pathlib.Path(__file__).with_name("host_driver.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

class BoundaryTests(unittest.TestCase):
    def test_frame_validation_rejects_partial_and_empty(self):
        valid = b"\0\x0c" + bytes(12)
        driver.validate_frames(valid + valid)
        for data in (b"", b"\0", valid[:-1], b"\0\x0b" + bytes(11), valid + b"\0"):
            with self.assertRaises(ValueError):
                driver.validate_frames(data)

    def test_base64_is_bounded_and_unique(self):
        packet = bytes(range(255))
        self.assertEqual(driver.decode(driver.encode(packet)), packet)
        for bad in ("AA=", "AB", "a!", "A" * 100000):
            with self.assertRaises(ValueError):
                driver.decode(bad)

    def test_peer_is_numeric_and_port_is_valid(self):
        self.assertEqual(driver.endpoint("[2001:db8::1]:53"), ("2001:db8::1", 53))
        for bad in ("example.org:53", "127.0.0.1:0", "127.0.0.1:65536", "::1"):
            with self.assertRaises(ValueError):
                driver.endpoint(bad)


class TransferDiagnosticTests(unittest.TestCase):
    @contextmanager
    def connection(self, *, response=None, error=None):
        enclave = Mock()
        enclave.post.return_value = response
        enclave.post.side_effect = error
        with patch.object(driver, "MAX_CONNECTION_SECONDS", 0.5), \
                driver.TransferServer(("127.0.0.1", 0), enclave) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=2) as client:
                    yield client, enclave
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_silent_client_timeout_keeps_warning_with_peer_and_zero_bytes(self):
        with self.assertLogs(driver.LOG, level="WARNING") as logged:
            with self.connection() as (client, enclave):
                peer = client.getsockname()
                self.assertEqual(client.recv(1), b"")
                enclave.post.assert_not_called()
        self.assertIn(f"peer={peer}", logged.output[0])
        self.assertIn("stage=request_length completed_requests=0", logged.output[0])
        self.assertIn("received=0 expected=2", logged.output[0])

    def test_partial_frame_timeout_reports_received_bytes(self):
        for packet, stage, received, expected in (
                (b"\0", "request_length", 1, 2),
                (b"\0\x0cabc", "request_body", 3, 12)):
            with self.subTest(stage=stage), self.assertLogs(driver.LOG, level="WARNING") as logged:
                with self.connection() as (client, enclave):
                    client.sendall(packet)
                    self.assertEqual(client.recv(1), b"")
                    enclave.post.assert_not_called()
            self.assertIn(f"stage={stage}", logged.output[0])
            self.assertIn(f"received={received} expected={expected}", logged.output[0])

    def test_backend_timeout_is_distinct_from_client_read_timeout(self):
        with self.assertLogs(driver.LOG, level="WARNING") as logged:
            with self.connection(error=TimeoutError("backend stalled")) as (client, enclave):
                client.sendall(b"\0\x0c" + bytes(12))
                self.assertEqual(client.recv(1), b"")
                enclave.post.assert_called_once()
        self.assertIn("stage=authority_request completed_requests=0", logged.output[0])
        self.assertIn("backend stalled", logged.output[0])

    def test_valid_reply_then_idle_preserves_transfer_and_reports_completed_request(self):
        frame = b"\0\x0c" + bytes(12)
        with self.assertLogs(driver.LOG, level="WARNING") as logged:
            with self.connection(response=frame) as (client, enclave):
                client.sendall(frame)
                response = bytearray()
                while len(response) < len(frame):
                    part = client.recv(len(frame) - len(response))
                    self.assertTrue(part, "connection closed before the complete DNS response")
                    response.extend(part)
                self.assertEqual(bytes(response), frame)
                self.assertEqual(client.recv(1), b"")
                enclave.post.assert_called_once_with("axfr", bytes(12), "application/dns-message", binary=True)
        self.assertIn("stage=request_length completed_requests=1", logged.output[0])
        self.assertIn("received=0 expected=2", logged.output[0])


class ResourceTests(unittest.TestCase):
    def test_transfer_frame_count_is_bounded(self):
        frame = b"\0\x0c" + bytes(12)
        driver.validate_frames(frame * driver.MAX_TRANSFER_FRAMES)
        with self.assertRaises(ValueError):
            driver.validate_frames(frame * (driver.MAX_TRANSFER_FRAMES + 1))

    def test_endpoints_are_canonical(self):
        for value in ("127.0.0.1:+53", "127.0.0.1:053", "2001:db8::1:53", "[2001:DB8::1]:53"):
            with self.assertRaises(ValueError):
                driver.endpoint(value)

    def test_slow_trickle_cannot_extend_absolute_deadline(self):
        from unittest.mock import Mock, patch
        stream = Mock()
        stream.recv.return_value = b"x"
        with patch.object(driver.time, "monotonic", side_effect=[1, 5, 11]):
            with self.assertRaises(TimeoutError):
                driver.exact(stream, 3, deadline=10)
        self.assertEqual(stream.recv.call_count, 2)
        self.assertEqual([call.args[0] for call in stream.settimeout.call_args_list], [9, 5])

    def test_http_reads_obey_specific_size_and_wall_time_bounds(self):
        from unittest.mock import Mock, patch
        response = Mock()
        response.read1.side_effect = lambda n: b"x" * n
        with self.assertRaises(ValueError):
            driver.bounded_response(response, 1232, 10)
        self.assertEqual(response.read1.call_args.args[0], 1233)
        response.read1.side_effect = [b"x", b"y"]
        with patch.object(driver.time, "monotonic", side_effect=[0, 1, 11]):
            with self.assertRaises(TimeoutError):
                driver.bounded_response(response, 1232, 10)

    def test_admission_happens_before_thread_creation(self):
        from unittest.mock import Mock, patch
        import socketserver
        for server_type, capacity in ((driver.TransferServer, driver.MAX_TCP_CONNECTIONS),
                                      (driver.UdpServer, driver.MAX_UDP_HANDLERS)):
            with server_type(("127.0.0.1", 0), Mock()) as server:
                for _ in range(capacity):
                    self.assertTrue(server.permits.acquire(blocking=False))
                with patch.object(socketserver.ThreadingMixIn, "process_request") as spawn, \
                        patch.object(server, "shutdown_request") as reject:
                    for _ in range(100):
                        server.process_request(Mock(), ("127.0.0.1", 12345))
                    spawn.assert_not_called()
                    self.assertEqual(reject.call_count, 100)
                for _ in range(capacity):
                    server.permits.release()

    def test_permit_released_when_handler_or_thread_start_fails(self):
        from unittest.mock import Mock, patch
        import socketserver
        with driver.TransferServer(("127.0.0.1", 0), Mock()) as server:
            with patch.object(socketserver.ThreadingMixIn, "process_request", side_effect=RuntimeError("thread startup")):
                with self.assertRaises(RuntimeError):
                    server.process_request(Mock(), ("127.0.0.1", 12345))
            self.assertTrue(server.permits.acquire(blocking=False))
            with patch.object(socketserver.ThreadingMixIn, "process_request_thread", side_effect=RuntimeError("handler")):
                with self.assertRaises(RuntimeError):
                    server.process_request_thread(Mock(), ("127.0.0.1", 12345))
            for _ in range(driver.MAX_TCP_CONNECTIONS):
                self.assertTrue(server.permits.acquire(blocking=False))
            self.assertFalse(server.permits.acquire(blocking=False))
            for _ in range(driver.MAX_TCP_CONNECTIONS):
                server.permits.release()

    def test_secondary_work_rows_fail_as_recoverable_value_errors(self):
        valid = {"id": "ab" * 16, "endpoint": "127.0.0.1:53", "kind": "soa",
                 "packet_base64url": driver.encode(bytes(12))}
        driver.validate_work(valid)
        for bad in (None, [], {}, dict(valid, id=1), dict(valid, endpoint=3),
                    dict(valid, kind=[]), dict(valid, packet_base64url="AB"), dict(valid, extra=1)):
            with self.assertRaises(ValueError):
                driver.validate_work(bad)

    def test_slow_secondary_work_does_not_block_maintenance(self):
        from unittest.mock import Mock, patch
        import concurrent.futures
        import threading
        stop = threading.Event()
        iterations = []
        work = [{"id": f"{i:032x}", "endpoint": "127.0.0.1:53", "kind": "soa",
                 "packet_base64url": driver.encode(bytes(12))} for i in range(256)]
        enclave = Mock()
        def post(path, body):
            if path == "maintenance":
                iterations.append(path)
                if len(iterations) == 3:
                    stop.set()
                return {"status": "committed"}
            return {"status": "committed", "work": work}
        enclave.post.side_effect = post
        executor = Mock()
        executor.submit.side_effect = lambda *args: concurrent.futures.Future()
        with patch.object(driver.concurrent.futures, "ThreadPoolExecutor", return_value=executor):
            driver.lifecycle(enclave, stop, 0)
        self.assertEqual(len(iterations), 3)
        self.assertEqual(executor.submit.call_count, driver.MAX_OUTSTANDING_EXCHANGES)
        executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_invalid_work_does_not_kill_lifecycle(self):
        from unittest.mock import Mock
        import threading
        stop = threading.Event()
        iterations = []
        enclave = Mock()
        def post(path, body):
            if path == "maintenance":
                iterations.append(path)
                if len(iterations) == 2:
                    stop.set()
                return {"status": "committed"}
            return {"status": "committed", "work": [{}]}
        enclave.post.side_effect = post
        driver.lifecycle(enclave, stop, 0)
        self.assertEqual(len(iterations), 2)


if __name__ == "__main__":
    unittest.main()
