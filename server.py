"""
Encrypted Chat Server
────────────────────────────
Usage : python server.py

Press Ctrl-C or type /quit to exit.
"""

import asyncio
import base64
import json
import logging
import os
import struct
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = "192.168.31.212"
PORT = 8443
LOG_FILE = "chat_server.log"

# ── ANSI colours for terminal ────────────────────────────────────────────────
G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; C = "\033[96m"; RST = "\033[0m"

# ── Logging ──────────────────────────────────────────────────────────────────

class ColourFormatter(logging.Formatter):
    COLOURS = {logging.INFO: G, logging.WARNING: Y, logging.ERROR: R, logging.DEBUG: C}
    def format(self, record):
        c = self.COLOURS.get(record.levelno, "")
        record.msg = f"{c}{record.msg}{RST}"
        return super().format(record)

def setup_logging():
    fmt = "%(asctime)s  %(levelname)-7s  %(message)s"
    date = "%H:%M:%S"
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt, datefmt=date))
    sh = logging.StreamHandler()
    sh.setFormatter(ColourFormatter(fmt, datefmt=date))
    log = logging.getLogger("chat")
    log.setLevel(logging.DEBUG)
    log.addHandler(fh)
    log.addHandler(sh)
    return log

log = setup_logging()

# ── Crypto helpers ────────────────────────────────────────────────────────────

def derive_session_key(priv, peer_pub_pem: str) -> bytes:
    peer = serialization.load_pem_public_key(peer_pub_pem.encode())
    shared = priv.exchange(ECDH(), peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"encrypted-chat-v2").derive(shared)

def aes_encrypt(key: bytes, plaintext: str) -> str:
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(key: bytes, payload: str) -> str:
    raw = base64.b64decode(payload)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()

# ── Framing (4-byte big-endian length prefix) ─────────────────────────────────

async def send_frame(writer: asyncio.StreamWriter, obj: dict):
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()

async def recv_frame(reader: asyncio.StreamReader) -> dict | None:
    hdr = await reader.readexactly(4)
    length, = struct.unpack(">I", hdr)
    if length > 10 * 1024 * 1024:
        raise ValueError(f"Frame too large: {length}")
    raw = await reader.readexactly(length)
    return json.loads(raw)

# ── Client session ────────────────────────────────────────────────────────────

class Session:
    def __init__(self, reader, writer):
        self.reader  = reader
        self.writer  = writer
        self.addr    = writer.get_extra_info("peername")
        self.key: bytes | None = None
        self.nick    = "anon"
        self.joined  = datetime.utcnow().isoformat(timespec="seconds")

    async def handshake(self, server_priv) -> bool:
        server_pub_pem = server_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        await send_frame(self.writer, {"type": "hello", "server_pub": server_pub_pem})

        msg = await recv_frame(self.reader)
        if not msg or msg.get("type") != "hello":
            return False
        self.nick = str(msg.get("nick", "anon"))[:32]
        try:
            self.key = derive_session_key(server_priv, msg["client_pub"])
            log.info("[ECDH] '%s' @ %s  →  session key OK", self.nick, self.addr)
            return True
        except Exception as exc:
            log.warning("[ECDH] '%s' key derivation failed: %s", self.nick, exc)
            return False

# ── Server ────────────────────────────────────────────────────────────────────

class Server:
    def __init__(self):
        self.sessions: dict[asyncio.StreamWriter, Session] = {}
        self.priv = generate_private_key(SECP256R1())
        self.total_msgs = 0

    # ── broadcast a plaintext payload to all sessions (optionally skip one) ──
    async def broadcast(self, sender_nick: str, plaintext: str,
                        ts: float, skip: asyncio.StreamWriter | None = None):
        dead = []
        for w, sess in list(self.sessions.items()):
            if w is skip:
                # Still send back to sender so they see their own message echo
                # (clients already display sent messages locally, so skip echo)
                continue
            try:
                enc = aes_encrypt(sess.key, plaintext)
                await send_frame(w, {
                    "type": "message",
                    "from": sender_nick,
                    "ts":   ts,
                    "cipher": enc,
                })
            except Exception:
                dead.append(w)
        for w in dead:
            await self._drop(w)

    async def _system(self, text: str, skip=None):
        """Broadcast a plain system notice (server-side text, encrypted per recipient)."""
        await self.broadcast("SERVER", f"*** {text}", time.time(), skip=skip)

    async def _drop(self, writer: asyncio.StreamWriter):
        sess = self.sessions.pop(writer, None)
        if not sess:
            return
        log.info("[DISC] '%s' disconnected  (%d online)", sess.nick, len(self.sessions))
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await self._system(f"{sess.nick} left the chat.")

    # ── per-client coroutine ──────────────────────────────────────────────────
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sess = Session(reader, writer)
        if not await sess.handshake(self.priv):
            writer.close()
            return

        self.sessions[writer] = sess
        log.info("[JOIN] '%s'  |  active: %d", sess.nick, len(self.sessions))

        # Tell everyone else someone joined
        await self._system(f"{sess.nick} joined the chat.", skip=writer)

        # Tell the newcomer who else is online
        others = [s.nick for w, s in self.sessions.items() if w is not writer]
        if others:
            enc = aes_encrypt(sess.key, f"*** Online: {', '.join(others)}")
            await send_frame(writer, {"type": "message", "from": "SERVER",
                                       "ts": time.time(), "cipher": enc})

        try:
            while True:
                msg = await recv_frame(reader)
                if msg is None:
                    break

                if msg.get("type") == "message":
                    try:
                        plain = aes_decrypt(sess.key, msg["cipher"])
                    except Exception:
                        log.warning("[DROP] bad auth tag from '%s'", sess.nick)
                        continue

                    self.total_msgs += 1
                    ts_now = time.time()
                    log.info("[MSG #%d] %s: %s  (enc=%d bytes)",
                             self.total_msgs, sess.nick, plain, len(msg["cipher"]))

                    # Forward to all OTHER clients
                    await self.broadcast(sess.nick, plain, ts_now, skip=writer)

        except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
            pass
        except Exception as exc:
            log.error("[ERR] '%s': %s", sess.nick, exc)
        finally:
            await self._drop(writer)

    async def run(self):
        srv = await asyncio.start_server(self.handle, HOST, PORT)
        log.info("═══════════════════════════════════════════════")
        log.info("  Encrypted Chat Server  —  listening on %s:%d", HOST, PORT)
        log.info("  Cipher  : AES-256-GCM | IV: 96-bit random")
        log.info("  KeyExch : ECDH P-256  | KDF: HKDF-SHA256")
        log.info("═══════════════════════════════════════════════")
        async with srv:
            await srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(Server().run())
    except KeyboardInterrupt:
        log.info("Server stopped.")
