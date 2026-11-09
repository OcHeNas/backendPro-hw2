import re
import sys

TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
CRLF = b"\r\n"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_line(data, offset, reason):
    end = data.find(CRLF, offset)
    require(end >= 0, reason)
    return data[offset:end], end + 2


def decode_chunks(data, offset):
    chunks = []
    while True:
        line, offset = read_line(data, offset, "bad_chunk")
        size_text = line.split(b";", 1)[0]
        require(re.fullmatch(rb"[0-9A-Fa-f]+", size_text), "bad_chunk")
        size = int(size_text, 16)
        if size == 0:
            while True:
                trailer, offset = read_line(data, offset, "bad_chunk")
                if not trailer:
                    return b"".join(chunks)
        end = offset + size
        require(end + 2 <= len(data) and data[end:end + 2] == CRLF, "bad_chunk")
        chunks.append(data[offset:end])
        offset = end + 2


def parse_message(data):
    start, offset = read_line(data, 0, "bad_start_line")
    request = re.fullmatch(b"(" + TOKEN + rb") ([\x21-\x7e]+) HTTP/1\.1", start)
    response = re.fullmatch(rb"HTTP/1\.1 ([0-9]{3}) ([\x09\x20-\x7e\x80-\xff]*)", start)
    if request:
        fields = [("type", "request"), ("method", request[1].decode("ascii")),
                  ("target", request[2].decode("ascii")), ("version", "HTTP/1.1")]
    elif response:
        fields = [("type", "response"), ("version", "HTTP/1.1"),
                  ("status", response[1].decode("ascii")),
                  ("reason", response[2].decode("latin-1"))]
    else:
        raise ValueError("bad_start_line")

    content_length = None
    chunked = False
    while True:
        line, offset = read_line(data, offset, "bad_header")
        if not line:
            break
        name, separator, value = line.partition(b":")
        require(separator and re.fullmatch(TOKEN, name), "bad_header")
        value = value.strip(b" \t")
        require(all(b == 9 or b >= 32 and b != 127 for b in value), "bad_header")
        name = name.lower()
        fields.append(("header", (name + b" " + value).decode("latin-1")))
        if name == b"content-length":
            require(re.fullmatch(rb"[0-9]+", value), "bad_header")
            try:
                length = int(value)
            except ValueError:
                raise ValueError("bad_header") from None
            require(content_length is None or content_length == length, "bad_header")
            content_length = length
        elif name == b"transfer-encoding":
            chunked |= value.lower() == b"chunked"

    if chunked:
        body = decode_chunks(data, offset)
    elif content_length is not None:
        require(content_length <= len(data) - offset, "incomplete_body")
        body = data[offset:offset + content_length]
    else:
        body = b""
    fields.append(("body.length", len(body)))
    if body and all(0x20 <= b <= 0x7E for b in body):
        fields.append(("body.text", body.decode("ascii")))
    return fields


def main():
    if len(sys.argv) != 1:
        print("usage: run.sh < message.http", file=sys.stderr)
        return 1
    try:
        for key, value in parse_message(sys.stdin.buffer.read()):
            print(key, value)
        return 0
    except ValueError as exc:
        print("error", exc)
        return 1
    except OSError as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
