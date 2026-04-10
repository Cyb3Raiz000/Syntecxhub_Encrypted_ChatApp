"""
Encrypted Chat Client
────────────────────────────
Usage : python client.py [nickname]

- Messages you send   appear as  "You ▶  <text>"  (green)
- Messages you receive appear as  "<Nick> ▶ <text>"  (cyan)
- Server notices appear in yellow

Press Ctrl-C or type /quit to exit.
"""

import asyncio
import base64
import json
import os
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = "192.168.31.212"
PORT = 8443

# ── ANSI colours ─────────────────────────────────────────────────────────────
GRN  = "\033[92m"   # your own messages
CYN  = "\033[96m"   # received messages
YLW  = "\033[93m"   # server / system notices
DIM  = "\033[2m"    # ciphertext hint
RST  = "\033[0m"
BOLD = "\033[1m"

def ts() -> str:
    return time.strftime("%H:%M:%S")

def print_recv(sender: str, text: str):
    """Print a received message, clearing the current input line first."""
    # \r\033[K  moves to column 0 and clears the line (erases the "You: " prompt)
    if sender == "SERVER":
        print(f"\r\033[K{YLW}{ts()} {text}{RST}")
    else:
        print(f"\r\033[K{CYN}{ts()} {BOLD}{sender}{RST}{CYN} ▶  {text}{RST}")
    print(f"{GRN}You:{RST} ", end="", flush=True)

# ── Crypto ────────────────────────────────────────────────────────────────────

def derive_key(priv, peer_pub_pem: str) -> bytes:
    peer = serialization.load_pem_public_key(peer_pub_pem.encode())
    shared = priv.exchange(ECDH(), peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"encrypted-chat-v2").derive(shared)

def encrypt(key: bytes, text: str) -> str:
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, text.encode(), None)
    return base64.b64encode(iv + ct).decode()

def decrypt(key: bytes, payload: str) -> str:
    raw = base64.b64decode(payload)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()

# ── Framing ───────────────────────────────────────────────────────────────────

async def send_frame(writer, obj: dict):
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()

async def recv_frame(reader) -> dict | None:
    try:
        hdr = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    length, = struct.unpack(">I", hdr)
    raw = await reader.readexactly(length)
    return json.loads(raw)

# ── Receive loop (runs as background task) ────────────────────────────────────

async def receive_loop(reader, key: bytes):
    while True:
        msg = await recv_frame(reader)
        if msg is None:
            print(f"\r\033[K{YLW}[!] Disconnected from server.{RST}")
            break

        if msg.get("type") != "message":
            continue

        try:
            plain = decrypt(key, msg["cipher"])
        except Exception:
            print(f"\r\033[K{YLW}[!] Decryption error — packet dropped.{RST}")
            print(f"{GRN}You:{RST} ", end="", flush=True)
            continue

        print_recv(msg.get("from", "?"), plain)

# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    # ── nickname ─────────────────────────────────────────────────────────────
    if len(sys.argv) > 1:
        nick = sys.argv[1].strip()[:32]
    else:
        nick = input("Enter your nickname: ").strip()[:32] or "anon"

    print(f"\n{YLW}Connecting to {HOST}:{PORT} …{RST}")

    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
    except ConnectionRefusedError:
        print(f"{YLW}[!] Cannot connect — is the server running?{RST}")
        print(f"    Run:  python server.py")
        return

    # ── ECDH handshake ────────────────────────────────────────────────────────
    priv   = generate_private_key(SECP256R1())
    my_pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    hello = await recv_frame(reader)
    if not hello or hello.get("type") != "hello":
        print(f"{YLW}[!] Bad handshake — server sent unexpected data.{RST}")
        return

    session_key = derive_key(priv, hello["server_pub"])

    await send_frame(writer, {
        "type":       "hello",
        "nick":       nick,
        "client_pub": my_pub,
    })

    print(f"{GRN}[✔] Connected as {BOLD}{nick}{RST}")
    print(f"{GRN}[✔] AES-256-GCM session active  "
          f"(key: {session_key.hex()[:16]}…){RST}")
    print(f"{DIM}    Type a message and press Enter.  /quit to exit.{RST}\n")

    # ── start background receiver ─────────────────────────────────────────────
    recv_task = asyncio.create_task(receive_loop(reader, session_key))

    loop = asyncio.get_event_loop()

    try:
        while True:
            print(f"{GRN}You:{RST} ", end="", flush=True)

            # read from stdin without blocking the event loop
            line = await loop.run_in_executor(None, sys.stdin.readline)
            text = line.rstrip("\n").strip()

            if not text:
                continue
            if text.lower() in ("/quit", "/exit", "/q"):
                break

            cipher = encrypt(session_key, text)
            await send_frame(writer, {"type": "message", "cipher": cipher})

            # Print own message (already cleared by prompt)
            print(f"\033[A\r\033[K"           # move up one line, clear it
                  f"{GRN}{ts()} {BOLD}You{RST}{GRN} ▶  {text}{RST}")
            print(f"{DIM}    [AES-256-GCM  "
                  f"cipher: {cipher[:32]}…]{RST}")

    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        recv_task.cancel()
        writer.close()
        print(f"\n{YLW}Connection closed.{RST}")


if __name__ == "__main__":
    asyncio.run(main())
