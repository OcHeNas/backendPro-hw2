import argparse
import http.client
import ipaddress
import random
import re
import socket
import sys
import time
from urllib.parse import urlsplit

RETRY_STATUSES = {429, 500, 502, 503, 504}
IDEMPOTENT = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}
TIMEOUT = 5.0
TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"


class DeadlineSocket(socket.socket):

    def remaining_timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("attempt exceeded 5 seconds")
        self.settimeout(remaining)

    def recv_into(self, buffer, nbytes=0, flags=0):
        self.remaining_timeout()
        return super().recv_into(buffer, nbytes, flags)

    def sendall(self, data, flags=0):
        self.remaining_timeout()
        return super().sendall(data, flags)


def server_address(host):
    if host.lower().rstrip(".") == "localhost":
        return ipaddress.ip_address("127.0.0.1")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        try:
            with open("/etc/hosts", encoding="utf-8") as hosts:
                for line in hosts:
                    parts = line.split("#", 1)[0].split()
                    if len(parts) > 1 and host.lower() in [s.lower() for s in parts[1:]]:
                        return ipaddress.ip_address(parts[0])
        except OSError:
            pass
        raise ValueError("use an IP address or a local hosts entry; external DNS is disabled") from None


def request_once(host, address, port, target, method, headers):
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    connection = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    with DeadlineSocket(family, socket.SOCK_STREAM) as sock:
        sock.deadline = time.monotonic() + TIMEOUT
        sock.remaining_timeout()
        try:
            sock.connect((str(address), port))
            connection.sock = sock
            connection.request(method, target, headers=headers)
            with connection.getresponse() as response:
                status = response.status
                retry_after = response.getheader("Retry-After")
                while response.read(65536):
                    pass
                if response.length not in (None, 0):
                    raise http.client.IncompleteRead(b"", response.length)
                if time.monotonic() >= sock.deadline:
                    raise TimeoutError("attempt exceeded 5 seconds")
                return status, retry_after
        finally:
            connection.close()


def pause_ms(next_attempt, retry_after):
    if retry_after is not None and re.fullmatch(r"[0-9]+", retry_after.strip()):
        return int(retry_after.strip()) * 1000
    ceiling = 2000 if next_attempt >= 5 else 200 * 2 ** (next_attempt - 1)
    return random.randint(0, ceiling)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--idempotency-key")
    args = parser.parse_args()
    try:
        if args.max_attempts < 1:
            raise ValueError("max-attempts must be positive")
        if not re.fullmatch(TOKEN, args.method):
            raise ValueError("invalid HTTP method")
        if any(ord(c) <= 32 or ord(c) == 127 for c in args.url):
            raise ValueError("URL contains whitespace or control characters")
        url = urlsplit(args.url)
        if url.scheme != "http" or not url.hostname or url.username is not None:
            raise ValueError("expected http://HOST[:PORT]/PATH without user information")
        port = url.port if url.port is not None else 80
        if not 1 <= port <= 65535:
            raise ValueError("port must be in 1..65535")
        target = (url.path or "/") + ("?" + url.query if url.query else "")
        target.encode("ascii")
        address = server_address(url.hostname)
        headers = {"Connection": "close"}
        if args.idempotency_key is not None:
            if not args.idempotency_key or any(
                    ord(c) < 32 or ord(c) == 127 for c in args.idempotency_key):
                raise ValueError("invalid Idempotency-Key")
            args.idempotency_key.encode("latin-1")
            headers["Idempotency-Key"] = args.idempotency_key

        can_retry = args.method in IDEMPOTENT or args.idempotency_key is not None
        for attempt in range(1, args.max_attempts + 1):
            status, retry_after = None, None
            try:
                status, retry_after = request_once(
                    url.hostname, address, port, target, args.method, headers)
                print("attempt", attempt, "status", status, flush=True)
            except (OSError, http.client.HTTPException) as exc:
                reason = " ".join(str(exc).split()) or type(exc).__name__
                print("attempt", attempt, "error", reason, flush=True)
            success = status is not None and 200 <= status <= 399
            retryable = status is None or status in RETRY_STATUSES
            if success or not retryable or not can_retry or attempt == args.max_attempts:
                print("result", "success" if success else "failure",
                      "attempts", attempt, flush=True)
                return 0 if success else 1
            delay = pause_ms(attempt + 1, retry_after)
            print("sleep_ms", delay, flush=True)
            time.sleep(delay / 1000)
    except (ValueError, OSError, OverflowError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
