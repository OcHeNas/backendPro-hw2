import re
import struct
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(header):
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_frame(frame):
    require(len(frame) >= 14, "incomplete Ethernet header")
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    fields = {
        "eth.dst": ":".join("%02x" % b for b in frame[:6]),
        "eth.src": ":".join("%02x" % b for b in frame[6:12]),
        "eth.ethertype": "0x%04x" % ethertype,
    }
    if ethertype != 0x0800:
        return fields

    ip = frame[14:]
    require(len(ip) >= 20, "incomplete IPv4 header")
    version, ihl = ip[0] >> 4, (ip[0] & 15) * 4
    total, ident, fragment = struct.unpack_from("!HHH", ip, 2)
    require(version == 4, "invalid IPv4 version")
    require(20 <= ihl <= len(ip), "invalid IPv4 header length")
    require(ihl <= total <= len(ip), "invalid IPv4 total length")
    header = bytearray(ip[:ihl])
    supplied_checksum = struct.unpack_from("!H", header, 10)[0]
    header[10:12] = b"\x00\x00"
    offset = (fragment & 0x1FFF) * 8
    flags = [name for bit, name in ((0x4000, "DF"), (0x2000, "MF"))
             if fragment & bit]
    fields.update({
        "ip.version": version,
        "ip.ihl_bytes": ihl,
        "ip.total_length": total,
        "ip.id": "0x%04x" % ident,
        "ip.flags": ",".join(flags) or "none",
        "ip.frag_offset": offset,
        "ip.ttl": ip[8],
        "ip.protocol": ip[9],
        "ip.src": ".".join(map(str, ip[12:16])),
        "ip.dst": ".".join(map(str, ip[16:20])),
        "ip.checksum_valid": str(checksum(header) == supplied_checksum).lower(),
    })
    data = ip[ihl:total]  
    payload_length = len(data)
    if offset:
        fields["payload.length"] = payload_length
        return fields
    if ip[9] == 6:
        require(len(data) >= 20, "incomplete TCP header")
        src, dst, seq, ack = struct.unpack_from("!HHII", data)
        tcp_length = (data[12] >> 4) * 4
        require(20 <= tcp_length <= len(data), "invalid TCP header length")
        flags = [name for bit, name in enumerate(
            ("FIN", "SYN", "RST", "PSH", "ACK", "URG")) if data[13] & (1 << bit)]
        fields.update({
            "tcp.src_port": src, "tcp.dst_port": dst,
            "tcp.seq": seq, "tcp.ack": ack,
            "tcp.data_offset_bytes": tcp_length,
            "tcp.flags": ",".join(flags) or "none",
            "tcp.window": struct.unpack_from("!H", data, 14)[0],
        })
        payload_length -= tcp_length
    elif ip[9] == 17:
        require(len(data) >= 8, "incomplete UDP header")
        src, dst, length = struct.unpack_from("!HHH", data)
        require(length >= 8, "invalid UDP length")
        require(length <= len(data) or fragment & 0x2000, "incomplete UDP datagram")
        fields.update({"udp.src_port": src, "udp.dst_port": dst, "udp.length": length})
        payload_length = min(length, len(data)) - 8
    fields["payload.length"] = payload_length
    return fields


def main():
    try:
        require(len(sys.argv) == 1, "usage: run.sh < frame.hex")
        text = re.sub(r"[\s:]", "", sys.stdin.read())
        require(bool(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", text)), "invalid hex dump")
        for key, value in parse_frame(bytes.fromhex(text)).items():
            print(key, value)
        return 0
    except (ValueError, OSError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())