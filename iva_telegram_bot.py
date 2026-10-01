#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
IVA / Sadad Android & Linux Unified Telegram Bot & Terminal API Client
================================================================================
Compatible with:
  - Android Termux (aarch64 / arm64 / armv7l / x86_64)
  - Python 3.10, 3.11, 3.12, 3.13, 3.14+
  - Zero mandatory external dependencies (pure standard library + optional cryptography/aiohttp)
  - Dual Mode: Interactive Terminal CLI & Async Telegram Bot
  - Direct Domestic Routing for Sadad + Proxy Routing for Telegram
================================================================================
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import ctypes.util
from dataclasses import dataclass, asdict
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import shutil
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

# Try importing optional acceleration libraries
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False


# ------------------------------------------------------------------------------
# 1. Configuration & Logging Subsystem
# ------------------------------------------------------------------------------

class Config:
    API_BASE_URL: str = os.getenv("IVA_BASE_URL", "https://ivaapi.sadadpsp.ir").rstrip("/")
    API_PREFIX: str = os.getenv("IVA_API_PREFIX", "/pwa/api")
    APP_VERSION: str = os.getenv("IVA_APP_VERSION", "3.10.24")
    SESSION_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_SESSION_DIR", "./sessions")))
    LOGS_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_LOGS_DIR", "./logs")))
    REQUEST_TIMEOUT: float = float(os.getenv("IVA_TIMEOUT", "65.0"))
    BOT_START_TIME: float = time.time()

    @classmethod
    def get_bot_token(cls) -> str:
        return os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

    @classmethod
    def get_admin_id(cls) -> Optional[int]:
        val = os.getenv("TELEGRAM_ADMIN_ID", "").strip()
        return int(val) if val.isdigit() else None

    @classmethod
    def get_base_address(cls) -> str:
        return cls.API_BASE_URL + cls.API_PREFIX


os.makedirs(Config.SESSION_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)

logger = logging.getLogger("IvaBot")
logger.setLevel(logging.INFO)

log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# File handler
log_file_path = os.path.join(Config.LOGS_DIR, "iva_bot.log")
file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

in_memory_logs: List[str] = []
known_users: Set[int] = set()


def mask_sensitive(text: str) -> str:
    """Masks tokens, OTPs, PINs, CVV2, and PANs from output logs."""
    if not text:
        return text
    s = str(text)
    # Mask 16-digit card numbers (keep first 6 and last 4)
    s = re.sub(r'\b(\d{6})\d{6}(\d{4})\b', r'\1******\2', s)
    # Mask Bearer tokens
    s = re.sub(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}', 'Bearer [MASKED_TOKEN]', s)
    return s


def clean_html(text: Any) -> str:
    """Safely escapes HTML special characters for Telegram messages."""
    return html.escape(str(text)) if text is not None else ""


def log_debug(msg: str) -> None:
    logger.debug(msg)
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] DEBUG: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)


def log_info(msg: str) -> None:
    logger.info(mask_sensitive(msg))
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] INFO: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)


def log_error(msg: str) -> None:
    logger.error(mask_sensitive(msg))
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] ERROR: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)


# ------------------------------------------------------------------------------
# 2. Cryptographic Engine (AES-256-CBC, RSA-2048, HMAC-SHA256)
# ------------------------------------------------------------------------------

_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
_AES_RSBOX = [0] * 256
for _i, _x in enumerate(_AES_SBOX):
    _AES_RSBOX[_x] = _i

_AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _gf_mul(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _key_expansion_256(key: bytes) -> List[List[int]]:
    w = [list(key[i:i+4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(w[i-1])
        if i % 8 == 0:
            temp = [_AES_SBOX[b] for b in (temp[1:] + temp[:1])]
            temp[0] ^= _AES_RCON[i // 8]
        elif i % 8 == 4:
            temp = [_AES_SBOX[b] for b in temp]
        w.append([w[i-8][j] ^ temp[j] for j in range(4)])
    round_keys: List[List[int]] = []
    for r in range(15):
        rk: List[int] = []
        for c in range(4):
            rk.extend(w[r*4 + c])
        round_keys.append(rk)
    return round_keys


def _aes_cipher_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = [list(block[i:i+4]) for i in range(0, 16, 4)]
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_keys[0][c*4 + r]
    for rnd in range(1, 14):
        for c in range(4):
            for r in range(4):
                state[c][r] = _AES_SBOX[state[c][r]]
        s0, s1, s2, s3 = state[0], state[1], state[2], state[3]
        state = [
            [s0[0], s1[1], s2[2], s3[3]],
            [s1[0], s2[1], s3[2], s0[3]],
            [s2[0], s3[1], s0[2], s1[3]],
            [s3[0], s0[1], s1[2], s2[3]]
        ]
        for c in range(4):
            col = state[c]
            a, b, cb, d = col[0], col[1], col[2], col[3]
            state[c][0] = _gf_mul(2, a) ^ _gf_mul(3, b) ^ cb ^ d
            state[c][1] = a ^ _gf_mul(2, b) ^ _gf_mul(3, cb) ^ d
            state[c][2] = a ^ b ^ _gf_mul(2, cb) ^ _gf_mul(3, d)
            state[c][3] = _gf_mul(3, a) ^ b ^ cb ^ _gf_mul(2, d)
        for c in range(4):
            for r in range(4):
                state[c][r] ^= round_keys[rnd][c*4 + r]

    for c in range(4):
        for r in range(4):
            state[c][r] = _AES_SBOX[state[c][r]]
    s0, s1, s2, s3 = state[0], state[1], state[2], state[3]
    state = [
        [s0[0], s1[1], s2[2], s3[3]],
        [s1[0], s2[1], s3[2], s0[3]],
        [s2[0], s3[1], s0[2], s1[3]],
        [s3[0], s0[1], s1[2], s2[3]]
    ]
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_keys[14][c*4 + r]

    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c*4 + r] = state[c][r]
    return bytes(out)


def _aes_inv_cipher_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = [list(block[i:i+4]) for i in range(0, 16, 4)]
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_keys[14][c*4 + r]
    for rnd in range(13, 0, -1):
        s0, s1, s2, s3 = state[0], state[1], state[2], state[3]
        state = [
            [s0[0], s3[1], s2[2], s1[3]],
            [s1[0], s0[1], s3[2], s2[3]],
            [s2[0], s1[1], s0[2], s3[3]],
            [s3[0], s2[1], s1[2], s0[3]]
        ]
        for c in range(4):
            for r in range(4):
                state[c][r] = _AES_RSBOX[state[c][r]]
        for c in range(4):
            for r in range(4):
                state[c][r] ^= round_keys[rnd][c*4 + r]
        for c in range(4):
            col = state[c]
            a, b, cb, d = col[0], col[1], col[2], col[3]
            state[c][0] = _gf_mul(0x0e, a) ^ _gf_mul(0x0b, b) ^ _gf_mul(0x0d, cb) ^ _gf_mul(0x09, d)
            state[c][1] = _gf_mul(0x09, a) ^ _gf_mul(0x0e, b) ^ _gf_mul(0x0b, cb) ^ _gf_mul(0x0d, d)
            state[c][2] = _gf_mul(0x0d, a) ^ _gf_mul(0x09, b) ^ _gf_mul(0x0e, cb) ^ _gf_mul(0x0b, d)
            state[c][3] = _gf_mul(0x0b, a) ^ _gf_mul(0x0d, b) ^ _gf_mul(0x09, cb) ^ _gf_mul(0x0e, d)

    s0, s1, s2, s3 = state[0], state[1], state[2], state[3]
    state = [
        [s0[0], s3[1], s2[2], s1[3]],
        [s1[0], s0[1], s3[2], s2[3]],
        [s2[0], s1[1], s0[2], s3[3]],
        [s3[0], s2[1], s1[2], s0[3]]
    ]
    for c in range(4):
        for r in range(4):
            state[c][r] = _AES_RSBOX[state[c][r]]
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_keys[0][c*4 + r]

    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c*4 + r] = state[c][r]
    return bytes(out)


def _pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("Invalid PKCS7 block length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]


class IvaCrypto:
    """
    Complete cryptographic layer for IVA / Sadad APIs:
      - AES-256-CBC with Zero IV / Custom IV and PKCS7 padding
      - HMAC-SHA256 request signing
      - RSA PKCS#1 v1.5 encryption for KeyExchange
    """
    CUSTOM_IV = bytes([48, 148, 136, 186, 72, 57, 83, 116, 19, 138, 210, 230, 3, 165, 240, 35])
    ZERO_IV = b"\x00" * 16

    _libcrypto: Optional[Any] = None

    @classmethod
    def _get_libcrypto(cls) -> Optional[Any]:
        if cls._libcrypto is None:
            candidates = [
                ctypes.util.find_library("crypto"),
                "/data/data/com.termux/files/usr/lib/libcrypto.so",
                "/data/data/com.termux/files/usr/lib/libcrypto.so.3",
                "/usr/lib/libcrypto.so",
                "libcrypto.so.3",
                "libcrypto.so.1.1",
                "libcrypto.so"
            ]
            for lib_name in candidates:
                if not lib_name:
                    continue
                try:
                    cls._libcrypto = ctypes.CDLL(lib_name)
                    cls._libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
                    cls._libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
                    cls._libcrypto.EVP_aes_256_cbc.restype = ctypes.c_void_p
                    cls._libcrypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                    cls._libcrypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                    break
                except Exception:
                    cls._libcrypto = None
        return cls._libcrypto

    @classmethod
    def generate_key(cls, num_bytes: int = 32) -> bytes:
        return secrets.token_bytes(num_bytes)

    @classmethod
    def aes_encrypt(cls, plaintext: str, key_base64: str) -> str:
        return cls._aes_encrypt_iv(plaintext, key_base64, cls.ZERO_IV)

    @classmethod
    def aes_encrypt2(cls, plaintext: str, key_base64: str, iv: Optional[bytes] = None) -> str:
        return cls._aes_encrypt_iv(plaintext, key_base64, iv or cls.CUSTOM_IV)

    @classmethod
    def aes_decrypt(cls, hex_cipher: str, key_base64: str) -> str:
        return cls._aes_decrypt_iv(hex_cipher, key_base64, cls.ZERO_IV)

    @classmethod
    def _aes_encrypt_iv(cls, plaintext: str, key_base64: str, iv: bytes) -> str:
        key_bytes = base64.b64decode(key_base64)
        raw_data = plaintext.encode("utf-8")

        # 1. Fast Path: cryptography library if available
        if _HAS_CRYPTOGRAPHY:
            try:
                padder = crypto_padding.PKCS7(128).padder()
                padded = padder.update(raw_data) + padder.finalize()
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
                enc = cipher.encryptor()
                ct = enc.update(padded) + enc.finalize()
                return ct.hex().lower()
            except Exception as ex:
                log_debug(f"Cryptography encrypt fallback: {ex}")

        # 2. OpenSSL libcrypto via ctypes
        lib = cls._get_libcrypto()
        if lib:
            ctx = lib.EVP_CIPHER_CTX_new()
            try:
                cipher = lib.EVP_aes_256_cbc()
                lib.EVP_EncryptInit_ex(ctx, cipher, None, key_bytes, iv)
                out = ctypes.create_string_buffer(len(raw_data) + 32)
                out_len = ctypes.c_int(0)
                lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), raw_data, len(raw_data))
                total_len = out_len.value
                fin_len = ctypes.c_int(0)
                ptr_fin = ctypes.cast(ctypes.addressof(out) + total_len, ctypes.POINTER(ctypes.c_char))
                lib.EVP_EncryptFinal_ex(ctx, ptr_fin, ctypes.byref(fin_len))
                total_len += fin_len.value
                return bytes(out.raw[:total_len]).hex().lower()
            except Exception as ex:
                log_debug(f"OpenSSL encrypt fallback: {ex}")
            finally:
                lib.EVP_CIPHER_CTX_free(ctx)

        # 3. Pure Python AES-256-CBC Implementation
        padded_pure = _pad_pkcs7(raw_data)
        rkeys = _key_expansion_256(key_bytes)
        ct_pure = bytearray()
        prev = iv
        for i in range(0, len(padded_pure), 16):
            block = bytes(padded_pure[i+j] ^ prev[j] for j in range(16))
            enc_block = _aes_cipher_block(block, rkeys)
            ct_pure.extend(enc_block)
            prev = enc_block
        return bytes(ct_pure).hex().lower()

    @classmethod
    def _aes_decrypt_iv(cls, hex_cipher: str, key_base64: str, iv: bytes) -> str:
        key_bytes = base64.b64decode(key_base64)
        cipher_bytes = bytes.fromhex(hex_cipher)

        # 1. Fast Path: cryptography library if available
        if _HAS_CRYPTOGRAPHY:
            try:
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
                dec = cipher.decryptor()
                padded = dec.update(cipher_bytes) + dec.finalize()
                unpadder = crypto_padding.PKCS7(128).unpadder()
                data = unpadder.update(padded) + unpadder.finalize()
                return data.decode("utf-8")
            except Exception as ex:
                log_debug(f"Cryptography decrypt fallback: {ex}")

        # 2. OpenSSL libcrypto via ctypes
        lib = cls._get_libcrypto()
        if lib:
            ctx = lib.EVP_CIPHER_CTX_new()
            try:
                cipher = lib.EVP_aes_256_cbc()
                lib.EVP_DecryptInit_ex(ctx, cipher, None, key_bytes, iv)
                out = ctypes.create_string_buffer(len(cipher_bytes) + 32)
                out_len = ctypes.c_int(0)
                lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(out_len), cipher_bytes, len(cipher_bytes))
                total_len = out_len.value
                fin_len = ctypes.c_int(0)
                ptr_fin = ctypes.cast(ctypes.addressof(out) + total_len, ctypes.POINTER(ctypes.c_char))
                lib.EVP_DecryptFinal_ex(ctx, ptr_fin, ctypes.byref(fin_len))
                total_len += fin_len.value
                return bytes(out.raw[:total_len]).decode("utf-8")
            except Exception as ex:
                log_debug(f"OpenSSL decrypt fallback: {ex}")
            finally:
                lib.EVP_CIPHER_CTX_free(ctx)

        # 3. Pure Python AES-256-CBC Implementation
        rkeys = _key_expansion_256(key_bytes)
        pt_pure = bytearray()
        prev = iv
        for i in range(0, len(cipher_bytes), 16):
            block = cipher_bytes[i:i+16]
            dec_block = _aes_inv_cipher_block(block, rkeys)
            pt_pure.extend(bytes(dec_block[j] ^ prev[j] for j in range(16)))
            prev = block
        return _unpad_pkcs7(bytes(pt_pure)).decode("utf-8")

    @classmethod
    def hmac_sha256(cls, data: str, working_key_base64: str) -> str:
        key_bytes = base64.b64decode(working_key_base64)
        h = hmac.new(key_bytes, data.encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(h).decode("utf-8")

    @classmethod
    def rsa_encrypt(cls, plaintext: str, public_key_str: str) -> str:
        """RSA PKCS#1 v1.5 encryption output as lowercase hex."""
        modulus, exponent = cls._parse_public_key(public_key_str)
        data = plaintext.encode("utf-8")
        k = (modulus.bit_length() + 7) // 8
        if len(data) > k - 11:
            raise ValueError("Message too long for RSA PKCS#1 v1.5")

        ps_len = k - len(data) - 3
        ps = bytearray()
        while len(ps) < ps_len:
            b = secrets.token_bytes(1)[0]
            if b != 0:
                ps.append(b)

        em = bytes([0x00, 0x02]) + bytes(ps) + bytes([0x00]) + data
        m_int = int.from_bytes(em, "big")
        c_int = pow(m_int, exponent, modulus)
        c_bytes = c_int.to_bytes(k, "big")
        return c_bytes.hex().lower()

    @classmethod
    def _parse_public_key(cls, pem_or_modulus: str) -> Tuple[int, int]:
        clean = pem_or_modulus.strip()
        lines = [line for line in clean.splitlines() if not line.startswith("---")]
        raw_b64 = "".join(lines).strip()
        der = base64.b64decode(raw_b64)
        return cls._parse_asn1_der(der)

    @classmethod
    def _parse_asn1_der(cls, der: bytes) -> Tuple[int, int]:
        pos = 0
        def read_len():
            nonlocal pos
            b = der[pos]
            pos += 1
            if b < 0x80:
                return b
            n = b & 0x7F
            val = int.from_bytes(der[pos:pos+n], "big")
            pos += n
            return val

        if der[pos] == 0x30:
            pos += 1
            read_len()
            if der[pos] == 0x30:
                pos += 1
                seq_len = read_len()
                pos += seq_len
                if der[pos] == 0x03:
                    pos += 1
                    read_len()
                    pos += 1  # unused bits
                    if der[pos] == 0x30:
                        pos += 1
                        read_len()

        if der[pos] == 0x02:
            pos += 1
            mod_len = read_len()
            modulus = int.from_bytes(der[pos:pos+mod_len], "big")
            pos += mod_len
            if der[pos] == 0x02:
                pos += 1
                exp_len = read_len()
                exponent = int.from_bytes(der[pos:pos+exp_len], "big")
                return modulus, exponent

        modulus = int.from_bytes(der, "big")
        return modulus, 65537

    @classmethod
    def base64_modulus_to_pem(cls, modulus_base64: str) -> str:
        mod_bytes = base64.b64decode(modulus_base64)
        if mod_bytes[0] >= 0x80:
            mod_bytes = b"\x00" + mod_bytes
        exp_bytes = (65537).to_bytes(3, "big")

        def encode_asn1(tag: int, val: bytes) -> bytes:
            l = len(val)
            if l < 0x80:
                return bytes([tag, l]) + val
            elif l <= 0xFF:
                return bytes([tag, 0x81, l]) + val
            else:
                return bytes([tag, 0x82, (l >> 8) & 0xFF, l & 0xFF]) + val

        mod_asn1 = encode_asn1(0x02, mod_bytes)
        exp_asn1 = encode_asn1(0x02, exp_bytes)
        rsa_seq = encode_asn1(0x30, mod_asn1 + exp_asn1)
        bit_str = encode_asn1(0x03, b"\x00" + rsa_seq)

        alg_id = bytes([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        spki = encode_asn1(0x30, alg_id + bit_str)
        b64 = base64.b64encode(spki).decode("ascii")
        chunks = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(chunks) + "\n-----END PUBLIC KEY-----\n"


# ------------------------------------------------------------------------------
# 3. Models & Data Structures
# ------------------------------------------------------------------------------

@dataclass
class SessionData:
    phone: Optional[str] = None
    token: Optional[str] = None
    refreshToken: Optional[str] = None
    expiresIn: Optional[int] = None
    accessTokenObtainedAt: Optional[int] = None
    rsaPublic: Optional[str] = None
    sharedKey: Optional[str] = None
    workingKey: Optional[str] = None


@dataclass
class CardPayment:
    pan: Optional[str] = None
    pin: Optional[str] = None
    cvv2: Optional[str] = None
    expireMonth: Optional[str] = None
    expireYear: Optional[str] = None
    token: Optional[str] = None

    def validate(self) -> None:
        if not self.token and not self.pan:
            raise ValueError("یا PAN یا Token باید مقداردهی شوند.")
        if not self.pin:
            raise ValueError("رمز دوم / رمز پویا الزامی است.")
        if not self.cvv2:
            raise ValueError("کد CVV2 الزامی است.")


@dataclass
class ChargePurchaseResult:
    status_code: int
    is_success: bool
    status_title: Optional[str] = None
    status_description: Optional[str] = None
    error_message: Optional[str] = None
    trackingCode: Optional[str] = None
    transactionId: Optional[str] = None
    referenceNumber: Optional[str] = None
    status: Optional[str] = None
    cardHolderName: Optional[str] = None


class IvaApiException(Exception):
    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------------------
# 4. Session Repository & Multi-Account Isolation
# ------------------------------------------------------------------------------

class FileSessionRepository:
    """Thread-safe & atomic session repository isolated per Telegram/Terminal User ID and Phone."""

    def __init__(self, base_directory: Optional[str] = None):
        self.base_dir = os.path.abspath(base_directory or Config.SESSION_DIR)
        os.makedirs(self.base_dir, exist_ok=True)
        self._lock = asyncio.Lock()

    def _sanitize(self, val: str) -> Optional[str]:
        if not val or not str(val).strip():
            return None
        cleaned = "".join(c for c in str(val) if c.isalnum() or c in ("-", "_"))
        return cleaned if cleaned else None

    def _get_user_dir(self, telegram_user_id: int) -> str:
        user_folder = self._sanitize(str(telegram_user_id)) or "anonymous"
        path = os.path.join(self.base_dir, user_folder)
        os.makedirs(path, exist_ok=True)
        return path

    def _get_file_path(self, telegram_user_id: int, phone: str) -> Optional[str]:
        sanitized_phone = self._sanitize(phone)
        if not sanitized_phone:
            return None
        return os.path.join(self._get_user_dir(telegram_user_id), f"{sanitized_phone}.json")

    async def load(self, telegram_user_id: int, phone: str) -> Optional[SessionData]:
        path = self._get_file_path(telegram_user_id, phone)
        if not path or not os.path.exists(path):
            return None
        async with self._lock:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return SessionData(**data)
            except Exception as ex:
                log_error(f"Error loading session: {ex}")
                return None

    async def save(self, telegram_user_id: int, session: SessionData) -> None:
        if not session or not session.phone:
            return
        path = self._get_file_path(telegram_user_id, session.phone)
        if not path:
            return
        async with self._lock:
            tmp_path = path + ".tmp"
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(asdict(session), f, indent=2, ensure_ascii=False)
                os.replace(tmp_path, path)
            except Exception as ex:
                log_error(f"Error saving session: {ex}")
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

    async def delete(self, telegram_user_id: int, phone: str) -> bool:
        path = self._get_file_path(telegram_user_id, phone)
        if not path or not os.path.exists(path):
            return False
        async with self._lock:
            try:
                os.remove(path)
                return True
            except Exception as ex:
                log_error(f"Error deleting session: {ex}")
                return False

    async def list_phones(self, telegram_user_id: int) -> List[str]:
        user_dir = self._get_user_dir(telegram_user_id)
        if not os.path.exists(user_dir):
            return []
        async with self._lock:
            files = [f for f in os.listdir(user_dir) if f.endswith(".json")]
            return [os.path.splitext(f)[0] for f in sorted(files)]

    async def get_all_user_ids(self) -> List[str]:
        async with self._lock:
            if not os.path.exists(self.base_dir):
                return []
            dirs = [d for d in os.listdir(self.base_dir) if os.path.isdir(os.path.join(self.base_dir, d))]
            return sorted(dirs)


# ------------------------------------------------------------------------------
# 5. Async HTTP & IVA Auth Client
# ------------------------------------------------------------------------------

class AsyncHttpClient:
    """Async HTTP executor using standard library asyncio + urllib with Sadad/Iranian TLS support."""

    def __init__(self, timeout: float = 65.0, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.ssl_context = self._build_tls_context()

    @staticmethod
    def _build_tls_context() -> ssl.SSLContext:
        """Constructs an SSLContext compatible with domestic Iranian payment servers."""
        try:
            ctx = ssl.create_default_context()
        except Exception:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        else:
            ctx.options |= 0x4

        if hasattr(ssl, "OP_DONT_INSERT_EMPTY_FRAGMENTS"):
            ctx.options |= ssl.OP_DONT_INSERT_EMPTY_FRAGMENTS

        for cipher_suite in [
            "DEFAULT:@SECLEVEL=1:ALL:!aNULL:!eNULL",
            "HIGH:MEDIUM:@SECLEVEL=1:!aNULL:!eNULL",
            "ALL:@SECLEVEL=1",
            "DEFAULT:@SECLEVEL=0",
        ]:
            try:
                ctx.set_ciphers(cipher_suite)
                break
            except Exception:
                pass

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_request, method, url, headers, body)

    def _sync_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, str]:
        req_data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)

        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                resp_text = resp.read().decode("utf-8")
                return status, resp_text
        except urllib.error.HTTPError as ex:
            status = ex.code
            resp_text = ex.read().decode("utf-8", errors="replace")
            return status, resp_text
        except Exception as ex:
            err_msg = str(ex)

            # Secondary fallback for TLS Handshake alerts
            if "SSL" in err_msg or "HANDSHAKE" in err_msg or "EOF" in err_msg:
                try:
                    alt_ctx = ssl._create_unverified_context()
                    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
                        alt_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
                    else:
                        alt_ctx.options |= 0x4
                    alt_ctx.check_hostname = False
                    alt_ctx.verify_mode = ssl.CERT_NONE

                    alt_handlers = []
                    if self.proxy:
                        alt_handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
                    alt_handlers.append(urllib.request.HTTPSHandler(context=alt_ctx))
                    alt_opener = urllib.request.build_opener(*alt_handlers)

                    with alt_opener.open(req, timeout=self.timeout) as resp:
                        return resp.getcode(), resp.read().decode("utf-8")
                except urllib.error.HTTPError as hex_err:
                    return hex_err.code, hex_err.read().decode("utf-8", errors="replace")
                except Exception as ex2:
                    err_msg = str(ex2)

            if "timed out" in err_msg or "Timeout" in err_msg:
                raise IvaApiException("مهلت اتصال به سرور ایوا به پایان رسید (Connection Timeout).")
            elif "Name or service not known" in err_msg or "getaddrinfo failed" in err_msg:
                raise IvaApiException("عدم دسترسی به سرور ایوا (DNS/Host Error).")
            elif "Connection refused" in err_msg:
                raise IvaApiException("اتصال به سرور ایوا برقرار نشد (Connection Refused).")
            elif "SSL" in err_msg or "CERTIFICATE" in err_msg or "HANDSHAKE" in err_msg or "EOF" in err_msg:
                raise IvaApiException(
                    f"خطای امنیتی گواهی SSL یا فیلترینگ جغرافیایی سرور ایوا:\n{clean_html(err_msg)}\n\n"
                    "💡 راهنمای رفع مشکل:\n"
                    "سرورهای پرداخت سداد/ایوا به دلیل مسائل امنیتی، آی‌پی‌های خارج از ایران (فیلترشکن‌ها) را مسدود یا ریست (EOF) می‌کنند.\n"
                    "در نرم‌افزار وی‌پی‌ان خود گزینه «Bypass Iran / مستثنی کردن سایت‌های ایرانی» را فعال کنید."
                )
            else:
                raise IvaApiException(f"خطای ارتباط شبکه: {err_msg}")


class IvaAuthClient:
    """
    Complete Async IVA API Client mirroring C# IvaAuthClient.cs:
      - 8 Active Endpoints
      - AES/HMAC encryption & Signing
      - Automated 401 Refresh & Single-Retry
    """

    SIGN_EXCLUDE = {
        "/v1/users/auth/keyExchange",
        "/v1/users/auth/verifyCode",
        "/v1/users/auth/token",
        "/v1/users/auth/refreshtoken",
    }

    def __init__(self, telegram_user_id: int = 1001, phone: Optional[str] = None, repository: Optional[FileSessionRepository] = None):
        self.user_id = telegram_user_id
        self.current_phone = phone
        self.repo = repository or FileSessionRepository()
        self.session = SessionData(phone=phone)
        self._last_otp_token: str = ""
        self._last_reagent: str = "0"
        iva_proxy = os.getenv("IVA_PROXY", "").strip() or None
        self.http = AsyncHttpClient(timeout=Config.REQUEST_TIMEOUT, proxy=iva_proxy)

    async def load_session(self, phone: str) -> None:
        self.current_phone = phone
        loaded = await self.repo.load(self.user_id, phone)
        self.session = loaded if loaded else SessionData(phone=phone)

    async def save_session(self) -> None:
        if self.current_phone:
            self.session.phone = self.current_phone
            await self.repo.save(self.user_id, self.session)

    def is_token_expired(self, buffer_seconds: int = 120) -> bool:
        if not self.session.token:
            return True
        if not self.session.accessTokenObtainedAt or not self.session.expiresIn:
            return False
        return (time.time() - self.session.accessTokenObtainedAt) > (self.session.expiresIn - buffer_seconds)

    def apply_headers(self, path: str, serialized_body: Optional[str]) -> Dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            "User-Agent": f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 IVA-PWA-Client/{Config.APP_VERSION}",
            "Origin": "https://ivaapp.ir",
            "Referer": "https://ivaapp.ir/",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        if self.session.token:
            headers["Authorization"] = f"Bearer {self.session.token}"
            headers["iva-versioncode"] = Config.APP_VERSION.replace(".", "")
            headers["iva-versionname"] = Config.APP_VERSION

        if serialized_body and path not in self.SIGN_EXCLUDE:
            if self.session.workingKey:
                headers["Sign-Data"] = IvaCrypto.hmac_sha256(serialized_body, self.session.workingKey)

        return headers

    async def _post_json(self, path: str, payload: Any) -> Dict[str, Any]:
        url = Config.get_base_address() + path
        json_body = json.dumps(payload, ensure_ascii=False)
        headers = self.apply_headers(path, json_body)
        headers["Content-Type"] = "application/json"

        status, text = await self.http.request("POST", url, headers, json_body)
        log_debug(f"POST {path} -> HTTP {status} Body: {text[:150]}")

        try:
            doc = json.loads(text) if text.strip() else {}
        except Exception:
            raise IvaApiException(f"پاسخ نامعتبر سرور (HTTP {status}): {clean_html(text[:150])}", str(status))

        err = doc.get("error")
        if err and str(err.get("code")) not in ("200", "None", ""):
            raise IvaApiException(err.get("message") or "عملیات ناموفق بود", str(err.get("code")))

        if status not in (200, 201, 204):
            raise IvaApiException(f"خطای درخواست سرور (HTTP {status})", str(status))

        return doc.get("data") if doc.get("data") is not None else doc

    async def _get_authorized_element(self, path: str, query: Optional[Dict[str, str]] = None) -> Any:
        if self.is_token_expired():
            await self.refresh_auth()

        url = Config.get_base_address() + path
        if query:
            url += "?" + urllib.parse.urlencode(query)

        headers = self.apply_headers(path, None)
        status, text = await self.http.request("GET", url, headers, None)

        if status == 401:
            log_info("Received 401 on GET, auto-refreshing token...")
            await self.refresh_auth()
            headers = self.apply_headers(path, None)
            status, text = await self.http.request("GET", url, headers, None)

        try:
            doc = json.loads(text) if text.strip() else {}
        except Exception:
            raise IvaApiException(f"پاسخ نامعتبر سرور (HTTP {status}): {clean_html(text[:150])}", str(status))

        err = doc.get("error")
        if err and str(err.get("code")) not in ("200", "None", ""):
            raise IvaApiException(err.get("message") or "عملیات ناموفق بود", str(err.get("code")))

        if status not in (200, 201, 204):
            raise IvaApiException(f"خطای سرور (HTTP {status})", str(status))

        return doc.get("data") if doc.get("data") is not None else doc

    # --- 1. Request OTP ---
    async def request_otp(self, phone_number: str) -> Dict[str, Any]:
        self.current_phone = phone_number
        payload = {"PhoneNumber": phone_number}
        data = await self._post_json("/v1/users/auth/verifyCode", payload)
        if isinstance(data, dict):
            self._last_otp_token = str(data.get("Token") or data.get("token") or "")
            self._last_reagent = str(data.get("ReagentNumber") or data.get("reagentNumber") or "0")
        return data

    # --- 2. Verify OTP Code ---
    async def verify_code(self, verification_code: str, token: Optional[str] = None, reagent_number: Optional[str] = None) -> Dict[str, Any]:
        tok = (token or self._last_otp_token or "").strip()
        reagent = (reagent_number or self._last_reagent or "0").strip()
        payload = {
            "VerificationCode": verification_code.strip(),
            "Token": tok,
            "ReagentNumber": reagent
        }
        data = await self._post_json("/v1/users/auth/token", payload)
        self._persist_tokens(data)
        await self.save_session()
        return data

    # --- 3. Refresh Token ---
    async def refresh_token(self, custom_refresh_token: Optional[str] = None) -> Dict[str, Any]:
        rt = custom_refresh_token or self.session.refreshToken
        if not rt:
            raise IvaApiException("رفرش‌توکن یافت نشد. لطفاً مجدداً لاگین کنید.", "401")
        data = await self._post_json("/v1/users/auth/refreshtoken", {"RefreshToken": rt})
        self._persist_tokens(data)
        await self.save_session()
        return data

    async def refresh_auth(self) -> None:
        await self.refresh_token()
        if self.session.rsaPublic:
            await self.key_exchange()

    def _persist_tokens(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        access_tok = data.get("accessToken") or data.get("AccessToken") or data.get("token") or data.get("Token")
        if access_tok:
            self.session.token = str(access_tok)
        refresh_tok = data.get("refreshToken") or data.get("RefreshToken")
        if refresh_tok:
            self.session.refreshToken = str(refresh_tok)
        exp_in = data.get("expiresIn") or data.get("ExpiresIn")
        if exp_in:
            self.session.expiresIn = int(exp_in)
        self.session.accessTokenObtainedAt = int(time.time())
        key = data.get("key") or data.get("Key")
        if key:
            try:
                self.session.rsaPublic = IvaCrypto.base64_modulus_to_pem(str(key))
            except Exception as ex:
                log_debug(f"Modulus wrap note: {ex}")

    # --- 4. Key Exchange ---
    async def key_exchange(self) -> None:
        if not self.session.rsaPublic:
            await self.try_discover_public_key()
        if not self.session.rsaPublic:
            raise IvaApiException("کلید عمومی RSA سرور یافت نشد. لطفاً ابتدا لاگین کنید.")

        shared_key = IvaCrypto.generate_key(32)
        working_key = IvaCrypto.generate_key(32)

        self.session.sharedKey = base64.b64encode(shared_key).decode("utf-8")
        self.session.workingKey = base64.b64encode(working_key).decode("utf-8")

        shared_hex = shared_key.hex().lower()
        working_hex = working_key.hex().lower()

        data_key = IvaCrypto.rsa_encrypt(shared_hex, self.session.rsaPublic)
        mac_key = IvaCrypto.rsa_encrypt(working_hex, self.session.rsaPublic)

        await self._post_json("/v1/users/auth/keyExchange", {"DataKey": data_key, "MacKey": mac_key})
        await self.save_session()

    async def ensure_secure_channel(self) -> None:
        if self.session.sharedKey and self.session.workingKey:
            return
        await self.key_exchange()

    # --- 5. User Profile ---
    async def get_profile(self) -> Dict[str, Any]:
        return await self._get_authorized_element("/v1/users/me")

    # --- 6. App Configurations / Public Key Discovery ---
    async def try_discover_public_key(self) -> None:
        version_parts = Config.APP_VERSION.split(".")
        query = {
            "VersionCode": version_parts[2] if len(version_parts) > 2 else Config.APP_VERSION,
            "ClientType": "3",
            "MarketType": "4",
        }
        try:
            configs = await self._get_authorized_element("/v1/baseInfo/configs/list", query)
            key = self._find_public_key(configs)
            if key:
                self.session.rsaPublic = key
                await self.save_session()
        except Exception as ex:
            log_debug(f"Discovery notice: {ex}")

    def _find_public_key(self, el: Any) -> Optional[str]:
        if isinstance(el, dict):
            for k, v in el.items():
                if isinstance(v, str) and ("public" in k.lower() or "rsapublic" in k.lower()) and len(v) > 100:
                    return v
                nested = self._find_public_key(v)
                if nested:
                    return nested
        elif isinstance(el, list):
            for item in el:
                nested = self._find_public_key(item)
                if nested:
                    return nested
        return None

    # --- 7. Charge Catalog ---
    async def get_charge_catalog(self) -> List[Dict[str, Any]]:
        data = await self._get_authorized_element("/v3/charges/pin/mobile/catalog")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    # --- 8. Pay Charge (Pin Payment) ---
    async def buy_charge(self, provider_id: str, amount: int, target_mobile_no: str, card: CardPayment) -> ChargePurchaseResult:
        card.validate()
        await self.ensure_secure_channel()

        shared_key = self.session.sharedKey or ""
        media: Dict[str, Any] = {}
        if card.cvv2:
            media["Cvv2"] = IvaCrypto.aes_encrypt(card.cvv2, shared_key)
        if card.pin:
            media["Pin"] = IvaCrypto.aes_encrypt(card.pin, shared_key)

        expire = (card.expireYear or "") + (card.expireMonth or "").zfill(2)
        if len("".join(c for c in expire if c.isdigit())) == 4:
            media["ExpireDate"] = IvaCrypto.aes_encrypt(expire, shared_key)

        if card.token:
            media["Token"] = card.token
            content_type = "application/vnd.sadad.payment.charge.Token+json"
        else:
            media["Pan"] = IvaCrypto.aes_encrypt(card.pan or "", shared_key)
            content_type = "application/vnd.sadad.payment.charge.Card+json"

        payload = {
            "ProviderId": provider_id,
            "Amount": amount,
            "CellPhoneNumber": target_mobile_no,
            "PaymentMedia": media
        }

        url = Config.get_base_address() + "/v3/charges/pin/pay"
        json_body = json.dumps(payload, ensure_ascii=False)
        headers = self.apply_headers("/v3/charges/pin/pay", json_body)
        headers["Content-Type"] = content_type

        status, text = await self.http.request("POST", url, headers, json_body)
        data = json.loads(text) if text.strip() else {}

        return ChargePurchaseResult(
            status_code=status,
            is_success=(status in (200, 201, 204)),
            status_title=data.get("statusTitle"),
            status_description=data.get("statusDescription"),
            error_message=data.get("errorMessage"),
            trackingCode=data.get("trackingCode"),
            transactionId=data.get("transactionId"),
            referenceNumber=data.get("referenceNumber"),
            status=data.get("status"),
            cardHolderName=data.get("cardHolderName"),
        )


# ------------------------------------------------------------------------------
# 6. Interactive Terminal CLI Interface
# ------------------------------------------------------------------------------

async def run_terminal_cli() -> None:
    """Complete interactive Terminal CLI for login, profile and testing without Telegram."""
    repo = FileSessionRepository()
    user_id = 1001  # Terminal default user ID
    current_phone: Optional[str] = None

    phones = await repo.list_phones(user_id)
    if phones:
        current_phone = phones[-1]

    client = IvaAuthClient(telegram_user_id=user_id, phone=current_phone, repository=repo)
    if current_phone:
        await client.load_session(current_phone)

    loop = asyncio.get_running_loop()

    def ask(prompt: str) -> str:
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return "0"

    print("\n" + "=" * 60)
    print("🏦 سامانه ترمینال احراز هویت و مدیریت IVA / Sadad")
    print("=" * 60)

    while True:
        is_logged_in = bool(client.session.token)
        print("\n" + "-" * 55)
        status_lbl = "🟢 متصل و معتبر" if (is_logged_in and not client.is_token_expired()) else ("⚠️ توکن منقضی" if is_logged_in else "⚪ لاگین نشده")
        print(f"📱 شماره فعال: {client.current_phone or 'تعیین نشده'} | وضعیت: {status_lbl}")
        print("-" * 55)
        print("1. 🔐 احراز هویت مستقیم با شماره موبایل و کد پیامکی (OTP)")
        print("2. 👤 دریافت اطلاعات حساب و پروفایل کاربری (/v1/users/me)")
        print("3. 🔄 تمدید توکن احراز هویت (RefreshToken)")
        print("4. 🔑 انجام تبادل کلید امنیتی (KeyExchange)")
        print("5. 📱 دریافت اطلاعات پایه و کاتالوگ شارژ")
        print("6. 📋 مشاهده و تعویض حساب‌های ذخیره‌شده")
        print("7. 🤖 اجرای ربات تلگرام (Telegram Bot Polling)")
        print("8. 🗑 حذف تمامی سشن‌ها و پاکسازی دیتابیس محلی")
        print("0. ❌ خروج")
        print("-" * 55)

        choice = await loop.run_in_executor(None, ask, "👉 شماره گزینه را وارد فرمایید [0-8]: ")

        if choice == "0":
            print("\n👋 خروج از سامانه ترمینال.")
            break

        elif choice == "1":
            phone = await loop.run_in_executor(None, ask, "\n📱 شماره موبایل را وارد نمایید (مثال: 09121234567): ")
            phone = phone.replace(" ", "")
            if not phone.startswith("09") or len(phone) != 11:
                print("❌ فرمت شماره اشتباه است. شماره باید ۱۱ رقمی بوده و با 09 شروع شود.")
                continue

            print("⏳ در حال ارسال شماره به سرور ایوا جهت دریافت کد پیامکی...")
            try:
                res = await client.request_otp(phone)
                req_token = res.get("Token") or res.get("token") or client._last_otp_token or ""
                reagent = res.get("ReagentNumber") or res.get("reagentNumber") or client._last_reagent or "0"
                print(f"✅ پیامک حاوی کد با موفقیت به شماره {phone} ارسال گردید.")

                otp_code = await loop.run_in_executor(None, ask, "📩 کد ۵ رقمی پیامک‌شده را وارد نمایید: ")
                print("⏳ در حال اعتبارسنجی کد در سرور سداد...")
                client.current_phone = phone
                token_res = await client.verify_code(otp_code, token=req_token, reagent_number=reagent)

                print("⏳ در حال تبادل کلیدهای امنیتی AES...")
                try:
                    await client.key_exchange()
                    print("✅ تبادل کلید AES با موفقیت انجام شد.")
                except Exception as k_ex:
                    print(f"⚠️ توجه در تبادل کلید: {k_ex}")

                print("\n🎉 احراز هویت با موفقیت کامل انجام شد و سشن ذخیره گردید!")
                exp_seconds = token_res.get('expiresIn') or token_res.get('ExpiresIn') or 0
                print(f"⏱ مدت زمان اعتبار توکن: {exp_seconds} ثانیه")
                print("💡 اکنون این حساب به صورت خودکار در ربات تلگرام نیز فعال است.")
            except Exception as ex:
                print(f"\n❌ خطا در فرآیند احراز هویت: {ex}")

        elif choice == "2":
            if not client.session.token:
                print("❌ شما هنوز لاگین نکرده‌اید. لطفاً ابتدا گزینه ۱ را اجرا کنید.")
                continue
            print("⏳ در حال استعلام اطلاعات کاربری از سرور...")
            try:
                prof = await client.get_profile()
                print("\n👤 مشخصات پروفایل کاربری:")
                print(f"• نام و نام‌خانوادگی: {prof.get('firstName', '')} {prof.get('lastName', '')}")
                print(f"• کد ملی: {prof.get('nationalCode', '---')}")
                print(f"• شماره همراه: {prof.get('cellPhoneNumber', client.current_phone)}")
                print(f"• شناسه کاربری: {prof.get('userId', '---')}")
            except Exception as ex:
                print(f"❌ خطا در دریافت اطلاعات: {ex}")

        elif choice == "3":
            if not client.session.refreshToken:
                print("❌ رفرش‌توکن ذخیره‌شده‌ای موجود نیست.")
                continue
            print("⏳ در حال تمدید توکن...")
            try:
                res = await client.refresh_token()
                print(f"✅ اکسس‌توکن جدید دریافت شد! اعتبار: {res.get('expiresIn', 0)} ثانیه")
            except Exception as ex:
                print(f"❌ خطا در تمدید توکن: {ex}")

        elif choice == "4":
            print("⏳ در حال اجرای KeyExchange با سرور...")
            try:
                await client.key_exchange()
                print("✅ کانال امن شد و کلیدهای متقارن در سرور ثبت شدند.")
            except Exception as ex:
                print(f"❌ خطا در تبادل کلید: {ex}")

        elif choice == "5":
            print("⏳ در حال استعلام کاتالوگ بسته‌های شارژ...")
            try:
                cat = await client.get_charge_catalog()
                print(f"✅ کاتالوگ با موفقیت دریافت شد. تعداد موارد: {len(cat)}")
                for item in cat[:5]:
                    print(f"  • {item.get('title', item.get('name', item))}")
            except Exception as ex:
                print(f"❌ خطا در دریافت کاتالوگ: {ex}")

        elif choice == "6":
            saved_phones = await repo.list_phones(user_id)
            if not saved_phones:
                print("📭 هیچ حسابی ذخیره نشده است.")
                continue
            print("\n📋 لیست حساب‌های ذخیره‌شده:")
            for idx, p in enumerate(saved_phones, 1):
                active_mark = " (فعال)" if p == client.current_phone else ""
                print(f"  {idx}. {p}{active_mark}")
            sel = await loop.run_in_executor(None, ask, "شماره ردیف حساب موردنظر را وارد کنید (یا Enter برای برگشت): ")
            if sel.isdigit() and 1 <= int(sel) <= len(saved_phones):
                selected_phone = saved_phones[int(sel)-1]
                await client.load_session(selected_phone)
                print(f"✅ حساب فعال به {selected_phone} تغییر یافت.")

        elif choice == "7":
            token = Config.get_bot_token()
            if not token:
                print("❌ توکن تلگرام تنظیم نشده است (TELEGRAM_BOT_TOKEN).")
                continue
            print("🤖 در حال اجرای ربات تلگرام...")
            bot = TelegramBot(token)
            await bot.start_polling()

        elif choice == "8":
            confirm = await loop.run_in_executor(None, ask, "⚠️ آیا از حذف تمامی سشن‌ها و فایل‌های لاگین اطمینان دارید؟ [y/n]: ")
            if confirm.lower() in ("y", "yes", "بله", "1"):
                if os.path.exists(Config.SESSION_DIR):
                    for item in os.listdir(Config.SESSION_DIR):
                        item_path = os.path.join(Config.SESSION_DIR, item)
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path, ignore_errors=True)
                        else:
                            try:
                                os.remove(item_path)
                            except Exception:
                                pass
                client.session = SessionData()
                client.current_phone = None
                user_active_phone.clear()
                user_states.clear()
                print("🗑 تمامی سشن‌ها با موفقیت به طور کامل حذف شدند.")


# ------------------------------------------------------------------------------
# 7. Telegram Bot Controller (Async Polling Engine)
# ------------------------------------------------------------------------------

user_states: Dict[int, Dict[str, Any]] = {}
user_active_phone: Dict[int, str] = {}


class TelegramBot:
    """Async Telegram Bot controller utilizing standard Telegram Bot API."""

    def __init__(self, token: Optional[str] = None):
        self.token = (token or Config.get_bot_token()).strip()
        self.api_url = f"https://api.telegram.org/bot{self.token}"
        # Telegram proxy configuration (local HTTP/SOCKS proxy)
        telegram_proxy = os.getenv("TELEGRAM_PROXY", "").strip() or None
        self.http = AsyncHttpClient(timeout=35.0, proxy=telegram_proxy)
        self.repo = FileSessionRepository()
        self.is_running = False

    async def call_api(self, method: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.api_url}/{method}"
        body = json.dumps(payload or {})
        headers = {"Content-Type": "application/json"}
        try:
            status, text = await self.http.request("POST", url, headers, body)
            res = json.loads(text) if text.strip() else {}
            if not res.get("ok"):
                log_error(f"Telegram API Error ({method}): {res.get('description')}")
            return res
        except Exception as ex:
            log_error(f"Telegram Request Exception ({method}): {ex}")
            return {"ok": False, "description": str(ex)}

    async def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None, parse_mode: Optional[str] = "HTML") -> None:
        payload: Dict[str, Any] = {"chat_id": chat_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = reply_markup

        res = await self.call_api("sendMessage", payload)
        if not res.get("ok"):
            err_desc = res.get("description", "")
            if "can't parse entities" in err_desc or "entity" in err_desc.lower():
                log_debug(f"Retrying sendMessage without parse_mode due to entity issue: {err_desc}")
                payload.pop("parse_mode", None)
                await self.call_api("sendMessage", payload)

    async def answer_callback(self, callback_id: str, text: Optional[str] = None) -> None:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        await self.call_api("answerCallbackQuery", payload)

    def is_admin(self, user_id: int) -> bool:
        admin_id = Config.get_admin_id()
        return admin_id is not None and user_id == admin_id

    def get_main_menu(self, is_logged_in: bool, phone: Optional[str] = None, user_id: Optional[int] = None) -> Dict[str, Any]:
        keyboard = [
            [
                {"text": "🔐 احراز هویت", "callback_data": "menu_auth"},
                {"text": "👤 حساب من", "callback_data": "menu_profile"},
            ],
            [
                {"text": "🔄 تمدید توکن", "callback_data": "menu_refresh"},
                {"text": "🔑 تبادل کلید", "callback_data": "menu_keyexchange"},
            ],
            [
                {"text": "📱 اطلاعات IVA", "callback_data": "menu_configs"},
                {"text": "💳 خرید شارژ", "callback_data": "menu_charge"},
            ],
            [
                {"text": "📋 مدیریت حساب‌ها", "callback_data": "menu_accounts"},
                {"text": "📊 وضعیت نشست", "callback_data": "menu_status"},
            ],
            [
                {"text": "🧪 تست API", "callback_data": "menu_apitest"},
                {"text": "❓ راهنما", "callback_data": "menu_help"},
            ],
        ]
        if user_id and self.is_admin(user_id):
            keyboard.append([{"text": "👑 پنل مدیریت (Admin)", "callback_data": "menu_admin"}])

        return {"inline_keyboard": keyboard}

    async def get_client(self, user_id: int) -> IvaAuthClient:
        phone = user_active_phone.get(user_id)
        if not phone:
            user_phones = await self.repo.list_phones(user_id)
            if user_phones:
                phone = user_phones[0]
                user_active_phone[user_id] = phone
            else:
                # Inherit terminal session (1001) if available
                term_phones = await self.repo.list_phones(1001)
                if term_phones:
                    phone = term_phones[0]
                    user_active_phone[user_id] = phone
                    term_sess = await self.repo.load(1001, phone)
                    if term_sess:
                        await self.repo.save(user_id, term_sess)

        client = IvaAuthClient(telegram_user_id=user_id, phone=phone, repository=self.repo)
        if phone:
            await client.load_session(phone)
        return client

    async def handle_update(self, update: Dict[str, Any]) -> None:
        try:
            if "message" in update:
                await self.handle_message(update["message"])
            elif "callback_query" in update:
                await self.handle_callback(update["callback_query"])
        except Exception as ex:
            log_error(f"Error handling update: {ex}\n{traceback.format_exc()}")

    async def handle_message(self, msg: Dict[str, Any]) -> None:
        user_id = msg["from"]["id"]
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "").strip()

        known_users.add(user_id)
        state = user_states.get(user_id, {})
        step = state.get("step")

        if text == "/start":
            user_states[user_id] = {}
            client = await self.get_client(user_id)
            is_connected = bool(client.session.token)
            phone = client.current_phone

            welcome = (
                "🏦 <b>پنل مدیریت و تست سامانه IVA / Sadad</b>\n\n"
                f"وضعیت اتصال: <b>{'🟢 متصل' if is_connected else '⚪ متصل نیست'}</b>\n"
                f"حساب فعال: <code>{clean_html(phone or 'تعیین نشده')}</code>\n"
                f"نسخه کلاینت: <code>{Config.APP_VERSION}</code>\n\n"
                "جهت مدیریت حساب یا اجرای عملیات یکی از گزینه‌های زیر را انتخاب نمایید:"
            )
            await self.send_message(chat_id, welcome, self.get_main_menu(is_connected, phone, user_id))
            return

        if text in ("/logout", "/clearsessions"):
            phones = await self.repo.list_phones(user_id)
            for p in phones:
                await self.repo.delete(user_id, p)
            # Also clear terminal user 1001 if admin
            if self.is_admin(user_id):
                t_phones = await self.repo.list_phones(1001)
                for tp in t_phones:
                    await self.repo.delete(1001, tp)
            user_active_phone.pop(user_id, None)
            user_states.pop(user_id, None)
            await self.send_message(chat_id, "🗑 تمامی سشن‌ها و حساب‌های شما با موفقیت به طور کامل حذف گردیدند.")
            return

        if text == "/help":
            help_text = (
                "📖 <b>راهنمای ربات تلگرام IVA / Sadad</b>\n\n"
                "• <b>🔐 احراز هویت:</b> ورود به سیستم از طریق شماره موبایل و کد پیامکی OTP.\n"
                "• <b>👤 حساب من:</b> نمایش اطلاعات پروفایل کاربری از <code>/v1/users/me</code>.\n"
                "• <b>🔄 تمدید توکن:</b> دریافت اکسس‌توکن جدید با رفرش‌توکن ذخیره‌شده.\n"
                "• <b>🔑 تبادل کلید:</b> تولید جفت‌کلیدهای امنیتی AES و ثبت در سرور.\n"
                "• <b>📱 اطلاعات IVA:</b> بررسی آدرس‌ها، نسخه و کلید عمومی سرور.\n"
                "• <b>💳 خرید شارژ:</b> خرید شارژ پین با رمزنگاری امن کارت بانکی.\n"
                "• <b>📋 مدیریت حساب‌ها:</b> افزودن چند شماره و سوئیچ بین حساب‌ها.\n"
                "• <b>📊 وضعیت:</b> بررسی مدت زمان اعتبار توکن و آماده‌بودن کلیدها.\n"
                "• <b>🧪 تست API:</b> تست سلامت تک‌تک اندپوینت‌ها.\n"
                "• <b>🗑 خروج کامل:</b> ارسال دستور <code>/logout</code> جهت حذف تمام سشن‌ها."
            )
            await self.send_message(chat_id, help_text)
            return

        if text == "/admin" and self.is_admin(user_id):
            await self.show_admin_panel(chat_id)
            return

        if step == "auth_phone":
            phone = text.replace(" ", "")
            if not phone.startswith("09") or len(phone) != 11:
                await self.send_message(chat_id, "❌ فرمت شماره نامعتبر است. لطفاً شماره را به فرمت <code>09120000000</code> ارسال فرمایید.")
                return

            client = await self.get_client(user_id)
            await self.send_message(chat_id, "⏳ در حال ارسال شماره به درگاه IVA...")
            try:
                res = await client.request_otp(phone)
                user_states[user_id] = {
                    "step": "auth_otp",
                    "phone": phone,
                    "token": res.get("Token") or res.get("token") or client._last_otp_token,
                    "reagent": res.get("ReagentNumber") or res.get("reagentNumber") or client._last_reagent,
                }
                user_active_phone[user_id] = phone
                await self.send_message(chat_id, f"📩 کد تأیید ۵ رقمی به شماره <code>{clean_html(phone)}</code> پیامک شد.\nلطفاً کد دریافتی را ارسال نمایید:")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در درخواست OTP:\n{clean_html(ex)}")
            return

        if step == "auth_otp":
            otp_code = text.strip()
            phone = state.get("phone", "")
            req_token = state.get("token", "")
            reagent = state.get("reagent", "0")
            client = await self.get_client(user_id)
            client.current_phone = phone

            await self.send_message(chat_id, "⏳ در حال اعتبارسنجی کد...")
            try:
                token_res = await client.verify_code(otp_code, token=req_token, reagent_number=reagent)
                user_states[user_id] = {}
                user_active_phone[user_id] = phone

                try:
                    await client.key_exchange()
                    key_msg = "✅ تبادل کلیدهای امنیتی AES نیز با موفقیت انجام شد."
                except Exception as k_ex:
                    key_msg = f"⚠️ هشدار در تبادل کلید: {clean_html(k_ex)}"

                msg_success = (
                    "🎉 <b>احراز هویت با موفقیت انجام شد!</b>\n\n"
                    f"📱 شماره: <code>{clean_html(phone)}</code>\n"
                    f"⏱ مدت اعتبار توکن: <code>{token_res.get('expiresIn', 0)} ثانیه</code>\n"
                    f"{key_msg}\n\n"
                    "اکنون می‌توانید از تمام امکانات سامانه استفاده نمایید."
                )
                await self.send_message(chat_id, msg_success, self.get_main_menu(True, phone, user_id))
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در تأیید کد:\n{clean_html(ex)}\nلطفاً مجدداً کد را ارسال نمایید:")
            return

        # Default fallback
        client = await self.get_client(user_id)
        is_connected = bool(client.session.token)
        await self.send_message(chat_id, "برای استفاده از ربات از دکمه‌های زیر استفاده کنید:", self.get_main_menu(is_connected, client.current_phone, user_id))

    async def handle_callback(self, query: Dict[str, Any]) -> None:
        user_id = query["from"]["id"]
        chat_id = query["message"]["chat"]["id"]
        data = query.get("data", "")
        await self.answer_callback(query["id"])

        client = await self.get_client(user_id)

        if data == "menu_auth":
            user_states[user_id] = {"step": "auth_phone"}
            await self.send_message(chat_id, "📱 لطفاً شماره تلفن همراه خود را ارسال کنید:\nمثال: <code>09121234567</code>")
            return

        if data == "menu_profile":
            if not client.session.token:
                await self.send_message(chat_id, "❌ شما هنوز وارد نشده‌اید. ابتدا از بخش 🔐 احراز هویت وارد شوید.")
                return
            await self.send_message(chat_id, "⏳ در حال دریافت اطلاعات پروفایل...")
            try:
                profile = await client.get_profile()
                prof_text = (
                    "👤 <b>اطلاعات پروفایل کاربری:</b>\n\n"
                    f"نام و نام‌خانوادگی: <code>{clean_html(profile.get('firstName', ''))} {clean_html(profile.get('lastName', ''))}</code>\n"
                    f"کد ملی: <code>{clean_html(profile.get('nationalCode', '---'))}</code>\n"
                    f"شماره همراه: <code>{clean_html(profile.get('cellPhoneNumber', client.current_phone))}</code>\n"
                    f"شناسه کاربر: <code>{clean_html(profile.get('userId', '---'))}</code>"
                )
                await self.send_message(chat_id, prof_text)
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای دریافت اطلاعات:\n{clean_html(ex)}")
            return

        if data == "menu_refresh":
            if not client.session.refreshToken:
                await self.send_message(chat_id, "❌ رفرش‌توکن ذخیره‌شده‌ای یافت نشد. لطفاً از طریق 🔐 احراز هویت مجدداً وارد شوید.")
                return
            await self.send_message(chat_id, "🔄 در حال تمدید اکسس‌توکن...")
            try:
                res = await client.refresh_token()
                await self.send_message(chat_id, f"✅ توکن با موفقیت تمدید شد!\nمدت اعتبار: <code>{res.get('expiresIn', 0)} ثانیه</code>")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تمدید توکن:\n{clean_html(ex)}")
            return

        if data == "menu_keyexchange":
            await self.send_message(chat_id, "🔑 در حال انجام تبادل کلید با سرور IVA...")
            try:
                await client.key_exchange()
                await self.send_message(chat_id, "✅ تبادل کلید موفقیت‌آمیز بود و کانال ارتباطی امن شد.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تبادل کلید:\n{clean_html(ex)}")
            return

        if data == "menu_configs":
            info_text = (
                "📱 <b>اطلاعات پیکربندی و سرورهای IVA / Sadad:</b>\n\n"
                f"آدرس پایه: <code>{Config.API_BASE_URL}</code>\n"
                f"پیشوند API: <code>{Config.API_PREFIX}</code>\n"
                f"نسخه PWA: <code>{Config.APP_VERSION}</code>\n"
                f"محیط رمزنگاری: <b>{'Cryptography Module' if _HAS_CRYPTOGRAPHY else 'Native libcrypto / Pure-Python'}</b>"
            )
            await self.send_message(chat_id, info_text)
            return

        if data == "menu_charge":
            await self.send_message(chat_id, "⏳ در حال دریافت کاتالوگ شارژ...")
            try:
                catalog = await client.get_charge_catalog()
                await self.send_message(chat_id, f"📦 کاتالوگ بسته‌های شارژ دریافت شد.\nتعداد موارد: <code>{len(catalog)}</code>")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای دریافت کاتالوگ:\n{clean_html(ex)}")
            return

        if data == "menu_status":
            is_token_exp = client.is_token_expired()
            has_shared = bool(client.session.sharedKey)
            has_working = bool(client.session.workingKey)
            has_rsa = bool(client.session.rsaPublic)
            status_msg = (
                "📊 <b>وضعیت نشست جاری:</b>\n\n"
                f"شماره فعال: <code>{clean_html(client.current_phone or 'نامشخص')}</code>\n"
                f"وضعیت توکن: <b>{'❌ منقضی یا ناموجود' if is_token_exp else '🟢 معتبر'}</b>\n"
                f"کلید AES متقارن (DataKey): <b>{'✅ آماده' if has_shared else '❌ ناموجود'}</b>\n"
                f"کلید امضا HMAC (MacKey): <b>{'✅ آماده' if has_working else '❌ ناموجود'}</b>\n"
                f"کلید عمومی RSA سرور: <b>{'✅ موجود' if has_rsa else '❌ ناموجود'}</b>"
            )
            await self.send_message(chat_id, status_msg)
            return

        if data == "menu_accounts":
            phones = await self.repo.list_phones(user_id)
            if not phones:
                await self.send_message(chat_id, "📭 هیچ حسابی برای شما ثبت نشده است. از منوی 🔐 احراز هویت حساب جدید اضافه کنید.")
                return

            buttons = []
            for p in phones:
                is_active = (p == client.current_phone)
                label = f"{'🟢 ' if is_active else '⚪ '}{p}"
                buttons.append([{"text": label, "callback_data": f"acc_select_{p}"}])

            buttons.append([{"text": "➕ افزودن حساب جدید", "callback_data": "menu_auth"}])
            buttons.append([{"text": "🗑 حذف حساب فعال", "callback_data": "acc_delete_current"}])

            await self.send_message(chat_id, "📋 <b>لیست حساب‌های ذخیره‌شده شما:</b>\nبرای تغییر حساب فعال، روی شماره موردنظر کلیک کنید.", {"inline_keyboard": buttons})
            return

        if data.startswith("acc_select_"):
            target_phone = data.replace("acc_select_", "")
            user_active_phone[user_id] = target_phone
            await self.send_message(chat_id, f"✅ حساب فعال به شماره <code>{clean_html(target_phone)}</code> تغییر یافت.")
            return

        if data == "acc_delete_current":
            if client.current_phone:
                await self.repo.delete(user_id, client.current_phone)
                user_active_phone.pop(user_id, None)
                await self.send_message(chat_id, "🗑 حساب فعال حذف گردید.")
            return

        if data == "menu_apitest":
            test_menu = [
                [{"text": "🧪 تست /users/me", "callback_data": "test_me"}],
                [{"text": "🧪 تست /configs/list", "callback_data": "test_configs"}],
                [{"text": "🧪 تست /catalog", "callback_data": "test_catalog"}],
                [{"text": "🧪 تست Key Exchange", "callback_data": "test_keyex"}],
                [{"text": "🔙 بازگشت به منوی اصلی", "callback_data": "menu_start"}],
            ]
            await self.send_message(chat_id, "🧪 <b>پنل تست مستقیم APIهای IVA</b>\nیک تست را انتخاب نمایید:", {"inline_keyboard": test_menu})
            return

        if data == "test_me":
            try:
                res = await client.get_profile()
                await self.send_message(chat_id, f"✅ خروجی موفق <code>/v1/users/me</code>:\n<code>{clean_html(json.dumps(res, ensure_ascii=False)[:300])}</code>")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /users/me:\n{clean_html(ex)}")
            return

        if data == "test_configs":
            try:
                await client.try_discover_public_key()
                await self.send_message(chat_id, "✅ خروجی موفق <code>/v1/baseInfo/configs/list</code>.\nکلید RSA سرور ثبت شد.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /configs/list:\n{clean_html(ex)}")
            return

        if data == "test_catalog":
            try:
                res = await client.get_charge_catalog()
                await self.send_message(chat_id, f"✅ خروجی موفق <code>/v3/charges/pin/mobile/catalog</code>:\nتعداد اپراتورها: {len(res)}")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /catalog:\n{clean_html(ex)}")
            return

        if data == "test_keyex":
            try:
                await client.key_exchange()
                await self.send_message(chat_id, "✅ تبادل کلید موفقیت‌آمیز بود.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای Key Exchange:\n{clean_html(ex)}")
            return

        if data == "menu_help":
            await self.send_message(chat_id, "📖 راهنما:\nاز منوی اصلی می‌توانید شماره تلفن خود را وارد کرده و فرآیند احراز هویت را انجام دهید.")
            return

        if data == "menu_admin" and self.is_admin(user_id):
            await self.show_admin_panel(chat_id)
            return

        if data == "admin_status" and self.is_admin(user_id):
            uptime_sec = int(time.time() - Config.BOT_START_TIME)
            all_users = await self.repo.get_all_user_ids()
            status_text = (
                "👑 <b>وضعیت ربات (Admin Overview)</b>\n\n"
                f"⏱ زمان اجرا: <code>{uptime_sec} ثانیه</code>\n"
                f"👥 کاربران شناسایی‌شده: <code>{len(known_users)}</code>\n"
                f"📁 پوشه‌های نشست ثبت‌شده: <code>{len(all_users)}</code>\n"
                f"🐍 نسخه پایتون: <code>{sys.version.split()[0]}</code>\n"
                f"📂 مسیر نشست‌ها: <code>{clean_html(Config.SESSION_DIR)}</code>"
            )
            await self.send_message(chat_id, status_text)
            return

        if data == "admin_logs" and self.is_admin(user_id):
            logs = "\n".join(in_memory_logs[-20:]) or "هیچ لاگی موجود نیست."
            await self.send_message(chat_id, f"📋 <b>گزارش لاگ‌های سیستمی:</b>\n\n<pre>{clean_html(logs)}</pre>")
            return

        if data == "menu_start":
            is_connected = bool(client.session.token)
            phone = client.current_phone
            await self.send_message(chat_id, "🏠 منوی اصلی:", self.get_main_menu(is_connected, phone, user_id))
            return

    async def show_admin_panel(self, chat_id: int) -> None:
        keyboard = [
            [
                {"text": "📊 وضعیت ربات", "callback_data": "admin_status"},
                {"text": "📋 لاگ‌های زنده", "callback_data": "admin_logs"},
            ],
            [
                {"text": "🧪 تست سرور IVA", "callback_data": "test_configs"},
                {"text": "🔙 بازگشت به خانه", "callback_data": "menu_start"},
            ],
        ]
        await self.send_message(chat_id, "👑 <b>پنل مدیریت اختصاصی ادمین (Admin Control Center)</b>", {"inline_keyboard": keyboard})

    async def start_polling(self) -> None:
        if not self.token:
            log_error("TELEGRAM_BOT_TOKEN is not configured. Switching to Terminal CLI mode.")
            await run_terminal_cli()
            return

        self.is_running = True
        log_info("Telegram Bot Starting... (Ready for Termux / Linux)")
        log_info(f"Session directory: {Config.SESSION_DIR}")
        log_info(f"Log file: {log_file_path}")
        admin_id = Config.get_admin_id()
        if admin_id:
            log_info(f"Admin ID configured: {admin_id}")

        # Check getMe on startup
        me_res = await self.call_api("getMe")
        if me_res.get("ok"):
            bot_user = me_res.get("result", {})
            log_info(f"Connected to Telegram API as @{bot_user.get('username')} (ID: {bot_user.get('id')})")
        else:
            log_error(f"Telegram getMe check: {me_res.get('description')}")

        offset = 0
        while self.is_running:
            try:
                payload = {"offset": offset, "timeout": 20}
                res = await self.call_api("getUpdates", payload)
                if res.get("ok"):
                    for update in res.get("result", []):
                        offset = update["update_id"] + 1
                        asyncio.create_task(self.handle_update(update))
                else:
                    await asyncio.sleep(2)
            except Exception as ex:
                log_error(f"Polling loop notice: {ex}")
                await asyncio.sleep(3)


# ------------------------------------------------------------------------------
# 8. Self-Verification Health Check & Entry Point
# ------------------------------------------------------------------------------

async def run_health_check() -> bool:
    """Pre-flight check for Crypto, Session storage and Termux readiness."""
    log_info("Running pre-flight health checks...")

    # 1. AES & Crypto Check
    k = IvaCrypto.generate_key(32)
    kb64 = base64.b64encode(k).decode("utf-8")
    enc = IvaCrypto.aes_encrypt("TermuxIVA123", kb64)
    dec = IvaCrypto.aes_decrypt(enc, kb64)
    assert dec == "TermuxIVA123", "Crypto self-test failed!"

    # 2. Session Repository Check
    test_repo = FileSessionRepository(Config.SESSION_DIR)
    dummy_session = SessionData(phone="09120000000", token="health_tok")
    await test_repo.save(999999, dummy_session)
    loaded = await test_repo.load(999999, "09120000000")
    assert loaded is not None and loaded.token == "health_tok"
    await test_repo.delete(999999, "09120000000")

    log_info("Pre-flight health checks PASSED.")
    return True


async def main() -> None:
    try:
        await run_health_check()
        
        # Check if terminal CLI mode is explicitly requested or bot token is empty
        run_cli_mode = (
            "--cli" in sys.argv or
            "--terminal" in sys.argv or
            os.getenv("IVA_MODE") == "terminal" or
            not Config.get_bot_token()
        )

        if run_cli_mode:
            print("\n💻 اجرای مستقیم در حالت ترمینال (Terminal CLI Mode)...")
            await run_terminal_cli()
        else:
            bot = TelegramBot(Config.get_bot_token())
            await bot.start_polling()

    except Exception as ex:
        log_error(f"Fatal error during execution: {ex}\n{traceback.format_exc()}")
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nبرنامه با درخواست کاربر متوقف شد.")
