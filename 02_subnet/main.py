import re
import sys


def ipv4(text):
    parts = text.split(".")
    if len(parts) != 4 or any(not re.fullmatch(r"[0-9]{1,3}", p) for p in parts):
        raise ValueError("invalid IPv4 address: " + text)
    address = 0
    for part in parts:
        octet = int(part, 10)
        if octet > 255:
            raise ValueError("IPv4 octet exceeds 255")
        address = (address << 8) | octet
    return address


def dotted(address):
    return ".".join(str((address >> shift) & 255) for shift in (24, 16, 8, 0))


def network(spec):
    parts = spec.split("/")
    if len(parts) != 2 or not re.fullmatch(r"[0-9]{1,2}", parts[1]):
        raise ValueError("expected IPv4/prefix")
    prefix = int(parts[1])
    if not 0 <= prefix <= 32:
        raise ValueError("prefix must be in 0..32")
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ipv4(parts[0]) & mask, prefix, mask


def subnet(spec):
    first, prefix, mask = network(spec)
    last = first | (0xFFFFFFFF ^ mask)
    ordinary = prefix < 31
    return {
        "network": dotted(first),
        "broadcast": dotted(last) if ordinary else "none",
        "netmask": dotted(mask), "prefix": prefix,
        "first": dotted(first + 1 if ordinary else first),
        "last": dotted(last - 1 if ordinary else last),
        "hosts": (1 << (32 - prefix)) - (2 if ordinary else 0),
    }


def route(path, destination):
    address = ipv4(destination)
    best = None
    with open(path, encoding="utf-8") as table:
        for number, line in enumerate(table, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                raise ValueError("invalid route on line %d" % number)
            net, prefix, mask = network(parts[0])
            if address & mask == net and (best is None or prefix > best[0]):
                best = prefix, parts[1]
    return best


def main():
    try:
        args = sys.argv[1:]
        if len(args) == 2 and args[0] == "subnet":
            fields = subnet(args[1])
        elif len(args) == 3 and args[0] == "route":
            best = route(args[1], args[2])
            if best is None:
                print("unreachable true")
                return 1
            fields = {"via": best[1], "prefix": best[0]}
        else:
            raise ValueError("usage: run.sh subnet IPv4/prefix | route FILE IPv4")
        for key, value in fields.items():
            print(key, value)
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print("error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())