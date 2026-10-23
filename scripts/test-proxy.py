#!/usr/bin/env python3
"""A tiny local proxy for scripts/verify-blocking.sh: HTTP CONNECT, plain HTTP (absolute URI), SOCKS5 and
SOCKS4/4a on one port, chosen by the client's first byte. Listens on 127.0.0.1 only.

    python3 -I scripts/test-proxy.py <port>
"""
import socket
import struct
import sys
import threading


def relay(a, b):
    def pump(src, dst):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.sendall(d)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join(5)
    a.close()
    b.close()


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d:
            raise OSError("closed")
        buf += d
    return buf


def recv_until(c, marker, limit=65536):
    buf = b""
    while marker not in buf:
        d = c.recv(4096)
        if not d or len(buf) > limit:
            raise OSError("closed")
        buf += d
    return buf


def socks5(c):
    n = recv_exact(c, 2)[1]
    recv_exact(c, n)
    c.sendall(b"\x05\x00")
    ver, cmd, _, atyp = recv_exact(c, 4)
    if atyp == 1:
        host = socket.inet_ntoa(recv_exact(c, 4))
    elif atyp == 3:
        host = recv_exact(c, recv_exact(c, 1)[0]).decode()
    else:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(c, 16))
    port = struct.unpack(">H", recv_exact(c, 2))[0]
    up = socket.create_connection((host, port), timeout=10)
    up.settimeout(None)
    c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    relay(c, up)


def socks4(c):
    head = recv_exact(c, 8)
    port = struct.unpack(">H", head[2:4])[0]
    rest = recv_until(c, b"\x00")
    host = socket.inet_ntoa(head[4:8])
    if head[4:7] == b"\x00\x00\x00" and head[7] != 0:
        name = rest.split(b"\x00", 1)[1]
        while not name.endswith(b"\x00"):
            name += c.recv(256)
        host = name[:-1].decode()
    up = socket.create_connection((host, port), timeout=10)
    up.settimeout(None)
    c.sendall(b"\x00\x5a" + b"\x00" * 6)
    relay(c, up)


def http(c, first):
    data = first + recv_until(c, b"\r\n\r\n") if b"\r\n\r\n" not in first else first
    head, _, body = data.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0].decode()
    method, target, version = line.split(" ")
    if method == "CONNECT":
        host, port = target.rsplit(":", 1)
        up = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
        up.settimeout(None)
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if body:
            up.sendall(body)
    else:
        rest = target.split("://", 1)[1]
        auth, _, path = rest.partition("/")
        host, _, port = auth.partition(":")
        up = socket.create_connection((host, int(port or 80)), timeout=10)
        up.settimeout(None)
        lines = head.split(b"\r\n")
        lines[0] = f"{method} /{path} {version}".encode()
        up.sendall(b"\r\n".join(lines) + b"\r\n\r\n" + body)
    relay(c, up)


def serve(c):
    try:
        first = c.recv(1, socket.MSG_PEEK)
        if first == b"\x05":
            socks5(c)
        elif first == b"\x04":
            socks4(c)
        else:
            http(c, c.recv(4096))
    except (OSError, ValueError, IndexError):
        c.close()


def main():
    port = int(sys.argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
