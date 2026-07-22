#!/usr/bin/env python3
"""Forge Reeden's encrypted Hive license preference offline.

The script appends a Hive CE frame whose key is "license" and whose value is
the JSON string consumed by Reeden's GZc license deserializer.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from Crypto.Cipher import AES


HIVE_STRING_TYPE = 0x04
HIVE_INT_TYPE = 0x01
HIVE_BOOL_TYPE = 0x03
HIVE_KEY_STRING_TYPE = 0x01

REEDEN_KEY_B64 = "EjRWeJq83vAaAhZqEOvvYAA+BGYiIkCSFukK"
REEDEN_SEED = (31, 122, 66)
REEDEN_LICENSE_HIVE_KEY = "license"
SUPPORTING_DEFAULT_TOKEN = "reedenhook-local-token"


def _build_crc32_table() -> list[int]:
    table: list[int] = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = 0xEDB88320 ^ (c >> 1) if c & 1 else c >> 1
        table.append(c)
    return table


CRC32_TABLE = _build_crc32_table()


def hive_crc32(data: bytes | bytearray | memoryview, crc: int = 0) -> int:
    """Hive CE Crc32.compute(), including its nonzero initial crc behavior."""
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def ror8(value: int, bits: int) -> int:
    value &= 0xFF
    return ((value >> bits) | ((value << (8 - bits)) & 0xFF)) & 0xFF


def derive_reeden_hive_key() -> bytes:
    """Reconstruct the 32-byte key generated near libapp.so:0x224e78c."""
    raw = base64.b64decode(REEDEN_KEY_B64)
    out: list[int] = []

    for index, value in enumerate(raw[8:]):
        acc = value
        for seed in REEDEN_SEED:
            acc = ror8(acc, 3) ^ seed
        acc = (acc - ((index % 7) + 5)) & 0xFF
        out.append(acc)

    out.extend([0] * (32 - len(out)))
    return bytes(out[:32])


def hive_key_crc(key: bytes) -> int:
    return hive_crc32(hashlib.sha256(key).digest())


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("invalid PKCS7 length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return data[:-pad_len]


def encode_hive_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([HIVE_STRING_TYPE]) + struct.pack("<I", len(raw)) + raw


def encode_hive_int(value: int) -> bytes:
    # Hive CE stores int values via BinaryWriter.writeDouble(value.toDouble()).
    return bytes([HIVE_INT_TYPE]) + struct.pack("<d", float(value))


def encode_hive_bool(value: bool) -> bytes:
    return bytes([HIVE_BOOL_TYPE, 1 if value else 0])


def decode_hive_string(value: bytes) -> str:
    if len(value) < 5 or value[0] != HIVE_STRING_TYPE:
        raise ValueError(f"not a Hive string value: first byte 0x{value[0]:02x}")
    length = struct.unpack_from("<I", value, 1)[0]
    raw = value[5 : 5 + length]
    if len(raw) != length:
        raise ValueError("truncated Hive string")
    return raw.decode("utf-8")


def decode_hive_value(value: bytes) -> object:
    if not value:
        raise ValueError("empty Hive value")
    type_id = value[0]
    if type_id == HIVE_STRING_TYPE:
        return decode_hive_string(value)
    if type_id == HIVE_INT_TYPE:
        if len(value) < 9:
            raise ValueError("truncated Hive int")
        return int(struct.unpack_from("<d", value, 1)[0])
    if type_id == HIVE_BOOL_TYPE:
        if len(value) < 2:
            raise ValueError("truncated Hive bool")
        return value[1] > 0
    return f"<unsupported type 0x{type_id:02x}: {value.hex()}>"


def encode_hive_key(key: str) -> bytes:
    raw = key.encode("utf-8")
    if len(raw) > 0xFF:
        raise ValueError("Hive string key is too long")
    return bytes([HIVE_KEY_STRING_TYPE, len(raw)]) + raw


def read_hive_key(frame_without_crc: bytes) -> tuple[str | int, int]:
    offset = 4
    key_type = frame_without_crc[offset]
    offset += 1
    if key_type == 0:
        key = struct.unpack_from("<I", frame_without_crc, offset)[0]
        return key, offset + 4
    if key_type == HIVE_KEY_STRING_TYPE:
        key_len = frame_without_crc[offset]
        offset += 1
        key = frame_without_crc[offset : offset + key_len].decode("utf-8")
        return key, offset + key_len
    raise ValueError(f"unsupported Hive key type: {key_type}")


def aes_encrypt_hive_value(plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    iv = iv if iv is not None else secrets.token_bytes(16)
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pkcs7_pad(plaintext))


def aes_decrypt_hive_value(encrypted: bytes, key: bytes) -> bytes:
    if len(encrypted) < 32 or len(encrypted[16:]) % 16:
        raise ValueError("encrypted Hive value has invalid length")
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(encrypted[16:]))


def build_encrypted_frame(key_name: str, value: str, key: bytes, iv: bytes | None = None) -> bytes:
    return build_encrypted_value_frame(key_name, encode_hive_string(value), key, iv)


def build_encrypted_value_frame(
    key_name: str,
    encoded_value: bytes,
    key: bytes,
    iv: bytes | None = None,
) -> bytes:
    encrypted_value = aes_encrypt_hive_value(encoded_value, key, iv)
    body = encode_hive_key(key_name) + encrypted_value
    frame_length = 4 + len(body) + 4
    frame_without_crc = struct.pack("<I", frame_length) + body
    crc = hive_crc32(frame_without_crc, hive_key_crc(key))
    return frame_without_crc + struct.pack("<I", crc)


@dataclass(frozen=True)
class HiveFrame:
    index: int
    offset: int
    length: int
    key: str | int
    value_offset: int
    crc: int
    crc_ok: bool
    deleted: bool


def iter_frames(data: bytes, key_crc: int = 0) -> Iterable[HiveFrame]:
    offset = 0
    index = 0
    while offset + 8 <= len(data):
        length = struct.unpack_from("<I", data, offset)[0]
        if length < 8 or offset + length > len(data):
            raise ValueError(f"invalid frame at 0x{offset:x}: length={length}")

        frame_without_crc = data[offset : offset + length - 4]
        stored_crc = struct.unpack_from("<I", data, offset + length - 4)[0]
        computed_crc = hive_crc32(frame_without_crc, key_crc)
        key, value_rel = read_hive_key(frame_without_crc)
        value_offset = offset + value_rel
        value_end = offset + length - 4
        yield HiveFrame(
            index=index,
            offset=offset,
            length=length,
            key=key,
            value_offset=value_offset,
            crc=stored_crc,
            crc_ok=computed_crc == stored_crc,
            deleted=value_offset == value_end,
        )
        offset += length
        index += 1

    if offset != len(data):
        raise ValueError(f"trailing bytes after frame parse: offset={offset}, size={len(data)}")


def decrypt_frame_value(data: bytes, frame: HiveFrame, key: bytes) -> str:
    if frame.deleted:
        raise ValueError("frame is a delete/tombstone")
    value_end = frame.offset + frame.length - 4
    encrypted = data[frame.value_offset:value_end]
    return decode_hive_string(aes_decrypt_hive_value(encrypted, key))


def decrypt_frame_plain_value(data: bytes, frame: HiveFrame, key: bytes) -> object:
    if frame.deleted:
        return "<deleted>"
    value_end = frame.offset + frame.length - 4
    encrypted = data[frame.value_offset:value_end]
    return decode_hive_value(aes_decrypt_hive_value(encrypted, key))


def make_license_json(email: str, license_key: str, order_id: str, activated_at: str) -> str:
    payload = {
        "email": email,
        "licenseKey": license_key,
        "valid": True,
        "orderId": order_id,
        "activatedAt": activated_at,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def parse_iv(value: str | None) -> bytes | None:
    if value is None:
        return None
    raw = bytes.fromhex(value)
    if len(raw) != 16:
        raise argparse.ArgumentTypeError("--iv-hex must decode to 16 bytes")
    return raw


def build_supporting_frames(
    *,
    key: bytes,
    email: str,
    license_key: str,
    access_token: str,
    last_check_time: int,
) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = [
        ("license_key", encode_hive_string(license_key)),
        ("license.email", encode_hive_string(email)),
        ("license.lastCheckOkTime", encode_hive_int(last_check_time)),
        ("license.lastCheckFailedCount", encode_hive_int(0)),
    ]
    if access_token:
        entries.append(("license.accessToken", encode_hive_string(access_token)))
    return [
        (name, build_encrypted_value_frame(name, encoded, key))
        for name, encoded in entries
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-i",
        "--input",
        default="artifacts/host/live_20260722/settings.hive",
        help="source settings.hive",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="artifacts/host/live_20260722/settings.forged.hive",
        help="output forged settings.hive",
    )
    parser.add_argument("--email", default="reedenhook@local")
    parser.add_argument("--license-key", default="RH-LOCAL-UNLOCK-1.36.1")
    parser.add_argument("--order-id", default="reedenhook-local")
    parser.add_argument("--activated-at", default="2026-07-22T00:00:00.000Z")
    parser.add_argument(
        "--supporting",
        action="store_true",
        help="also append supporting license cache preferences",
    )
    parser.add_argument(
        "--access-token",
        default=SUPPORTING_DEFAULT_TOKEN,
        help="supporting mode value for license.accessToken; empty string skips it",
    )
    parser.add_argument(
        "--last-check-time",
        type=int,
        default=int(time.time()),
        help="supporting mode value for license.lastCheckOkTime (epoch seconds)",
    )
    parser.add_argument("--iv-hex", help="optional deterministic 16-byte IV hex for testing")
    parser.add_argument("--list", action="store_true", help="list parsed Hive frames before writing")
    parser.add_argument(
        "--list-values",
        action="store_true",
        help="decrypt and print primitive values while listing; implies --list",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    key = derive_reeden_hive_key()
    key_crc = hive_key_crc(key)

    data = input_path.read_bytes()
    frames = list(iter_frames(data, key_crc))
    bad = [frame for frame in frames if not frame.crc_ok]
    if bad:
        raise SystemExit(
            "CRC verification failed for frames: "
            + ", ".join(f"#{frame.index}@0x{frame.offset:x}" for frame in bad[:8])
        )

    if args.list or args.list_values:
        for frame in frames:
            suffix = "deleted" if frame.deleted else "value"
            decoded = ""
            if args.list_values and isinstance(frame.key, str):
                try:
                    value = decrypt_frame_plain_value(data, frame, key)
                    if isinstance(value, str) and len(value) > 180:
                        value = value[:177] + "..."
                    decoded = f" {suffix}={value!r}"
                except Exception as exc:
                    decoded = f" value=<decode-error:{exc}>"
            print(
                f"#{frame.index:03d} off=0x{frame.offset:05x} "
                f"len={frame.length:04d} key={frame.key!r} "
                f"{'deleted' if frame.deleted else 'crc=ok'}{decoded}"
            )
        return 0

    license_json = make_license_json(
        args.email,
        args.license_key,
        args.order_id,
        args.activated_at,
    )
    forged_frame = build_encrypted_frame(
        REEDEN_LICENSE_HIVE_KEY,
        license_json,
        key,
        parse_iv(args.iv_hex),
    )
    frames_to_add: list[tuple[str, bytes]] = [(REEDEN_LICENSE_HIVE_KEY, forged_frame)]
    if args.supporting:
        frames_to_add.extend(
            build_supporting_frames(
                key=key,
                email=args.email,
                license_key=args.license_key,
                access_token=args.access_token,
                last_check_time=args.last_check_time,
            )
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data + b"".join(frame for _, frame in frames_to_add))

    forged_data = output_path.read_bytes()
    forged_frames = list(iter_frames(forged_data, key_crc))
    added_frames = forged_frames[-len(frames_to_add) :]
    license_frame = next(
        frame for frame in reversed(added_frames) if frame.key == REEDEN_LICENSE_HIVE_KEY
    )
    decoded = decrypt_frame_value(forged_data, license_frame, key)
    decoded_json = json.loads(decoded)
    if decoded_json.get("valid") is not True:
        raise SystemExit("forged license verification failed")

    print(f"input:  {input_path}")
    print(f"output: {output_path}")
    print(f"key:    {key.hex()}")
    print(f"keyCrc: 0x{key_crc:08x}")
    print(f"frames: {len(frames)} -> {len(forged_frames)}")
    for added in added_frames:
        value = decrypt_frame_plain_value(forged_data, added, key)
        print(f"added:  key={added.key!r} length={added.length} value={value!r}")
    print(f"value:  {decoded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
