"""Small bounded HTTP helpers for explicit local validation clients."""
import socket
import threading
import time


class SocketDeadline:
    """Bound headers, body and TLS operations on an already-connected socket.

    A per-read timeout alone allows a byte trickle to extend a response forever.
    One daemon timer closes this single request's socket at its absolute deadline.
    Numeric socket connection establishment has its own bounded connect timeout.
    """
    def __init__(self, stream, deadline):
        self.stream = stream
        self.deadline = deadline
        self.expired = threading.Event()
        self.timer = None

    def __enter__(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP request deadline exceeded")
        self.stream.settimeout(remaining)
        def abort():
            self.expired.set()
            try:
                self.stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.timer = threading.Timer(remaining, abort)
        self.timer.daemon = True
        self.timer.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.timer.cancel()
        self.timer.join(timeout=1)
        if self.expired.is_set() or time.monotonic() >= self.deadline:
            raise TimeoutError("HTTP request deadline exceeded") from None
        return False


def read_bounded(response, maximum, deadline):
    data = bytearray()
    while len(data) <= maximum:
        if time.monotonic() >= deadline:
            raise TimeoutError("HTTP response deadline exceeded")
        chunk = response.read1(min(65536, maximum + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise ValueError("HTTP response exceeds byte bound")
