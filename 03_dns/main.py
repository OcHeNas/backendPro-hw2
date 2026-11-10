import ipaddress
import secrets
import socket
import struct
import sys
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {value: key for key, value in TYPES.items()}
STATUSES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
TIMEOUT = 5.0


def require(condition, message="malformed DNS message"):
    if not condition:
        raise ValueError(message)


class IncompleteMessage(ValueError):
    """В сообщении не хватает байтов для очередного поля."""


def require_complete(condition):
    if not condition:
        raise IncompleteMessage("incomplete DNS message")


def encode_name(name):
    if name == ".":
        return b"\x00"
    labels = name.removesuffix(".").split(".")
    wire = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        require(1 <= len(raw) <= 63, "DNS label must contain 1..63 bytes")
        wire.append(len(raw))
        wire.extend(raw)
    wire.append(0)
    require(len(wire) <= 255, "DNS name exceeds 255 bytes")
    return bytes(wire)


def read_name(message, offset):
    labels, visited = [], set()
    end = None
    expanded_length = 1
    while True:
        require_complete(0 <= offset < len(message))
        require(offset not in visited)
        visited.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            require_complete(offset + 1 < len(message))
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        require(length & 0xC0 == 0)
        offset += 1
        if length == 0:
            return ".".join(labels) + ".", end if end is not None else offset
        require_complete(offset + length <= len(message))
        expanded_length += length + 1
        require(expanded_length <= 255)
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length


def record_value(message, rtype, start, end):
    raw = message[start:end]
    if rtype == 1:
        require(len(raw) == 4)
        return str(ipaddress.IPv4Address(raw))
    if rtype == 28:
        require(len(raw) == 16)
        return str(ipaddress.IPv6Address(raw))
    if rtype in (2, 5, 15):
        preference = ""
        if rtype == 15:
            require(len(raw) >= 3)
            preference = str(struct.unpack_from("!H", message, start)[0]) + " "
            start += 2
        name, next_offset = read_name(message, start)
        require(next_offset == end)
        return preference + name
    if rtype == 16:
        parts = []
        while start < end:
            length = message[start]
            start += 1
            require(start + length <= end)
            parts.append(message[start:start + length])
            start += length
        return b"".join(parts).decode("utf-8", errors="replace")
    return None


def parse_response(message):
    require(len(message) >= 12)
    _, flags, qd, an, ns, ar = struct.unpack_from("!6H", message)
    require(flags & 0x8000 and not flags & 0x7800, "not a DNS query response")
    truncated = bool(flags & 0x0200)
    rcode = flags & 15
    answers, lifetimes = [], []
    try:
        offset = 12
        for _ in range(qd):
            _, offset = read_name(message, offset)
            require_complete(offset + 4 <= len(message))
            offset += 4
        for index in range(an + ns + ar):
            _, offset = read_name(message, offset)
            require_complete(offset + 10 <= len(message))
            rtype, rclass, ttl, length = struct.unpack_from("!HHIH", message, offset)
            start = offset + 10
            offset = start + length
            require_complete(offset <= len(message))
            if index < an:
                lifetimes.append(ttl)
                if rtype in TYPE_NAMES and rclass == 1:
                    value = record_value(message, rtype, start, offset)
                    answers.append("%s %s %d" % (TYPE_NAMES[rtype], value, ttl))
    except IncompleteMessage:
        if not truncated:
            raise
    status = STATUSES.get(rcode, "RCODE%d" % rcode)
    ttl = min(lifetimes) if lifetimes and rcode == 0 and not truncated else 0
    return status, answers, ttl


def query(server, port, name, qtype):
    ident = secrets.randbits(16)
    request = (struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0)
               + encode_name(name) + struct.pack("!HH", qtype, 1))
    family = socket.AF_INET if server.version == 4 else socket.AF_INET6
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((str(server), port))
        deadline = time.monotonic() + TIMEOUT
        sock.settimeout(TIMEOUT)
        sock.send(request)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("DNS response timeout")
            sock.settimeout(remaining)
            reply = sock.recv(65535)
            if len(reply) < 2 or struct.unpack_from("!H", reply)[0] != ident:
                continue
            return parse_response(reply)


def main():
    try:
        require(len(sys.argv) == 3, "usage: run.sh SERVER_IP PORT")
        server = ipaddress.ip_address(sys.argv[1])
        port = int(sys.argv[2])
        require(1 <= port <= 65535, "port must be in 1..65535")
        cache = {}
        for line in sys.stdin:
            if not line.strip():
                continue
            parts = line.split()
            require(len(parts) == 2, "expected NAME TYPE")
            name, type_name = parts
            require(type_name.upper() in TYPES, "unsupported DNS type")
            encode_name(name) 
            qtype = TYPES[type_name.upper()]
            key = (name.removesuffix(".").lower(), qtype)
            print("query", name, type_name, flush=True)
            cached = cache.get(key)
            if cached is not None and time.monotonic() < cached[0]:
                status, answers = cached[1:]
            else:
                cache.pop(key, None)
                try:
                    status, answers, ttl = query(server, port, name, qtype)
                except OSError as exc:
                    print("status TIMEOUT\nend", flush=True)
                    print("error:", exc, file=sys.stderr)
                    return 1
                except ValueError as exc:
                    print("status FORMERR\nend", flush=True)
                    print("error:", exc, file=sys.stderr)
                    return 1
                if ttl > 0:
                    cache[key] = (time.monotonic() + ttl, status, answers)
            print("status", status)
            for answer in answers:
                print("answer", answer)
            print("end", flush=True)
        return 0
    except (ValueError, OSError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())