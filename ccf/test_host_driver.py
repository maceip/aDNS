import importlib.util
import pathlib
import unittest

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
