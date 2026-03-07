import asyncio
import json
import base64
import time
from enum import Enum, auto
from typing import Optional, Dict, Set

from protocol import encode_msg, decode_line, make_hello, new_msg_id
from identity import load_or_create_identity

from nacl.signing import VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder, RawEncoder
from nacl.hash import sha256
import nacl.utils

import hashlib
from contacts import load_contacts, get_contact


ACK_TIMEOUT = 3.0
MAX_RETRIES = 7


class State(Enum):
    DISCONNECTED = auto()
    CONNECTED = auto()
    HANDSHAKE = auto()
    SECURE = auto()
    CLOSED = auto()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


class PeerNode:
    def __init__(self, name: str):
        self.name = name
        self.state = State.DISCONNECTED

        self.signing_key, self.verify_key, self.peer_id = load_or_create_identity()

        self.eph_priv: Optional[PrivateKey] = None
        self.remote_peer_id: Optional[str] = None
        self.remote_eph_pub: Optional[PublicKey] = None

        self.session_key: Optional[bytes] = None
        self.box: Optional[SecretBox] = None

        self.writer: Optional[asyncio.StreamWriter] = None
        self._input_task_started = False
        self._retry_task_started = False

        self.seq = 0
        self.outbox: Dict[str, dict] = {}
        self.seen: Set[str] = set()

    async def handle_connection(self, reader, writer):
        self.state = State.CONNECTED
        self.writer = writer
        await self.send_raw(make_hello(self.peer_id, "*"))
        await self.read_loop(reader)

    async def connect_to(self, host: str, port: int, remote_hint: str = "*"):
        reader, writer = await asyncio.open_connection(host, port)
        self.state = State.CONNECTED
        self.writer = writer
        await self.send_raw(make_hello(self.peer_id, remote_hint))
        await self.read_loop(reader)

    async def read_loop(self, reader: asyncio.StreamReader):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = decode_line(line)
                await self.on_message(msg)
        finally:
            self.state = State.CLOSED
            print("Connection closed")
            if self.writer:
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass

    async def send_raw(self, msg: dict):
        if not self.writer:
            return
        self.writer.write(encode_msg(msg))
        await self.writer.drain()

    async def ensure_ephemeral(self):
        if self.eph_priv is None:
            self.eph_priv = PrivateKey.generate()

    async def send_hs1(self, remote_peer_id: str):
        await self.ensure_ephemeral()
        self.state = State.HANDSHAKE
        self.remote_peer_id = remote_peer_id

        eph_pub_bytes = bytes(self.eph_priv.public_key)
        sig = self.signing_key.sign(eph_pub_bytes).signature

        hs1 = {
            "v": 1,
            "type": "HS1",
            "from": self.peer_id,
            "to": remote_peer_id,
            "payload": {
                "ik_pub": self.verify_key.encode(encoder=Base64Encoder).decode(),
                "ek_pub": b64e(eph_pub_bytes),
                "sig": b64e(sig),
            }
        }
        await self.send_raw(hs1)

    async def process_hs1(self, msg: dict):
        payload = msg["payload"]

        remote_peer_id = msg.get("from")
        remote_ik_pub_b64 = payload["ik_pub"]
        remote_ek_pub_bytes = b64d(payload["ek_pub"])
        remote_sig = b64d(payload["sig"])

        peer_id_check = hashlib.sha256(remote_ik_pub_b64.encode("utf-8")).hexdigest()
        if peer_id_check != remote_peer_id:
            print("Peer ID mismatch (possible spoof)")
            return

        db = load_contacts()
        c = get_contact(db, remote_peer_id)
        if c is None:
            print(f"Unknown contact {remote_peer_id}. Import contact card first.")
            return
        if c["ik_pub"] != remote_ik_pub_b64:
            print("Contact pubkey mismatch! Possible MITM or stale contact.")
            return

        vk = VerifyKey(remote_ik_pub_b64, encoder=Base64Encoder)
        try:
            vk.verify(remote_ek_pub_bytes, remote_sig)
        except Exception:
            print("Signature verification failed")
            return

        self.remote_peer_id = remote_peer_id
        self.remote_eph_pub = PublicKey(remote_ek_pub_bytes)

        await self.ensure_ephemeral()

        if self.state not in (State.HANDSHAKE, State.SECURE):
            await self.send_hs1(self.remote_peer_id)

        await self.derive_session_key()

    async def derive_session_key(self):
        if not (self.eph_priv and self.remote_eph_pub):
            return

        dh_box = Box(self.eph_priv, self.remote_eph_pub)
        shared = dh_box.shared_key()

        self.session_key = sha256(shared, encoder=RawEncoder)[:32]
        self.box = SecretBox(self.session_key)
        self.state = State.SECURE
        print("SECURE session established")

        if not self._input_task_started:
            self._input_task_started = True
            asyncio.create_task(self.input_loop())

        if not self._retry_task_started:
            self._retry_task_started = True
            asyncio.create_task(self.retry_loop())

    async def send_secure_inner(self, inner_obj: dict):
        if not self.box or not self.remote_peer_id:
            print("Not secure yet")
            return

        nonce = nacl.utils.random(24)
        plaintext = json.dumps(inner_obj, ensure_ascii=False).encode("utf-8")
        encrypted = self.box.encrypt(plaintext, nonce)

        outer = {
            "v": 1,
            "type": "SECURE",
            "from": self.peer_id,
            "to": self.remote_peer_id,
            "payload": {
                "nonce": b64e(nonce),
                "ciphertext": b64e(encrypted.ciphertext),
            }
        }
        await self.send_raw(outer)

    async def send_chat(self, text: str):
        if self.state != State.SECURE or not self.remote_peer_id:
            print("Not ready yet")
            return

        self.seq += 1
        msg_id = new_msg_id()

        inner = {
            "inner": "CHAT",
            "msg_id": msg_id,
            "seq": self.seq,
            "text": text,
        }

        self.outbox[msg_id] = {
            "inner": inner,
            "sent_at": time.time(),
            "retries": 0,
        }

        await self.send_secure_inner(inner)

    async def send_ack(self, ack_id: str, seq: int, status: str):
        inner = {
            "inner": "ACK",
            "ack_id": ack_id,
            "seq": seq,
            "status": status,
        }
        await self.send_secure_inner(inner)

    async def retry_loop(self):
        while self.state != State.CLOSED:
            if self.state == State.SECURE:
                now = time.time()
                for msg_id, entry in list(self.outbox.items()):
                    if now - entry["sent_at"] > ACK_TIMEOUT:
                        if entry["retries"] >= MAX_RETRIES:
                            print(f"[{self.peer_id}] FAILED {msg_id}")
                            del self.outbox[msg_id]
                            continue
                        entry["retries"] += 1
                        entry["sent_at"] = now
                        print(f"[{self.peer_id}] RETRY {msg_id} ({entry['retries']})")
                        await self.send_secure_inner(entry["inner"])
            await asyncio.sleep(1.0)

    async def on_message(self, msg: dict):
        mtype = msg.get("type")

        if mtype == "HELLO":
            await self.send_hs1(msg.get("from"))

        elif mtype == "HS1":
            await self.process_hs1(msg)

        elif mtype == "SECURE":
            if not self.box:
                print("Got SECURE before session established; ignoring")
                return

            nonce = b64d(msg["payload"]["nonce"])
            ciphertext = b64d(msg["payload"]["ciphertext"])

            try:
                plaintext = self.box.decrypt(ciphertext, nonce)
            except Exception:
                print("Decrypt failed")
                return

            inner = json.loads(plaintext.decode("utf-8"))
            it = inner.get("inner")

            if it == "CHAT":
                msg_id = inner["msg_id"]
                seq = inner["seq"]
                text = inner["text"]

                if msg_id in self.seen:
                    await self.send_ack(msg_id, seq, "dup")
                    return

                self.seen.add(msg_id)
                print(f"\n[REMOTE] {text}")
                await self.send_ack(msg_id, seq, "ok")

            elif it == "ACK":
                ack_id = inner["ack_id"]
                status = inner["status"]

                if ack_id in self.outbox:
                    del self.outbox[ack_id]
                    print(f"[{self.peer_id}] DELIVERED {ack_id} ({status})")

            else:
                print(f"Unknown inner: {inner}")

    async def input_loop(self):
        while self.state == State.SECURE:
            text = await asyncio.to_thread(input, "")
            if text.strip():
                await self.send_chat(text)