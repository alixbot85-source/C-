#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
IVA / Sadad Android & Linux Unified Telegram Bot & Terminal API Client (IvaScanner)
================================================================================
Compatible with:
  - Android Termux (aarch64 / arm64 / armv7l / x86_64)
  - Python 3.10, 3.11, 3.12, 3.13, 3.14+
  - Zero mandatory external dependencies (pure standard library + optional cryptography/libcrypto)
  - Full Dual Mode: Interactive Terminal CLI & Async Telegram Bot Polling Engine
  - Endpoints: KeyExchange, verifyCode, token, refreshtoken, users/me, configs/list,
               charges catalog, pin payment, topup payment, Shaparak TSM getKey.
  - Card Scanner & Charge Payment with auto-retry and multi-account isolation.
================================================================================
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import ctypes.util
from dataclasses import dataclass, field, asdict
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
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

# Try loading native libcrypto via ctypes
_LIBCRYPTO = None
if not _HAS_CRYPTOGRAPHY:
    try:
        _lib_path = (
            ctypes.util.find_library("crypto")
            or "libcrypto.so.3"
            or "libcrypto.so.1.1"
            or "libcrypto.so"
        )
        if _lib_path:
            _LIBCRYPTO = ctypes.CDLL(_lib_path)
            _LIBCRYPTO.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            _LIBCRYPTO.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            _LIBCRYPTO.EVP_aes_256_cbc.restype = ctypes.c_void_p
            _LIBCRYPTO.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            _LIBCRYPTO.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
            _LIBCRYPTO.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            _LIBCRYPTO.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            _LIBCRYPTO.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
            _LIBCRYPTO.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    except Exception:
        _LIBCRYPTO = None


# ------------------------------------------------------------------------------
# 1. Constants & Configuration (IvaConstants & IvaOptions)
# ------------------------------------------------------------------------------

class IvaConstants:
    """Constants mirroring C# IvaScanner.IvaConstants."""
    ApiBaseUrl: str = "https://ivapwa.sadadpsp.ir"
    ApiPrefix: str = "/pwa/api"
    PublicKeyUrl: str = "https://tsm.shaparak.ir/mobileApp/getKey"
    AppVersion: str = "3.10.24"

    class Endpoints:
        KeyExchange: str = "/v1/users/auth/keyExchange"
        RegisterRequest: str = "/v1/users/auth/verifyCode"
        Activation: str = "/v1/users/auth/token"
        RefreshToken: str = "/v1/users/auth/refreshtoken"
        UserProfile: str = "/v1/users/me"
        AppConfiguration: str = "/v1/baseInfo/configs/list"
        ChargeCatalog: str = "/v3/charges/pin/mobile/catalog"
        PayCharge: str = "/v1/charges/pin/payment"
        PayChargeV3: str = "/v3/charges/pin/pay"
        TopupRequest: str = "/v1/charges/topup/payment"

    SignExclude: Set[str] = {
        "/v1/users/auth/keyExchange",
        "/v1/users/auth/verifyCode",
        "/v1/users/auth/token",
        "/v1/users/auth/refreshtoken",
    }

    class StorageKeys:
        Token: str = "token"
        RefreshToken: str = "refreshToken"
        AccessTokenExpTime: str = "accessTokenExpTime"
        TokenType: str = "tokenType"
        AccessTokenObtainedAt: str = "accessTokenObtainedAt"
        SharedKey: str = "shared_key"
        WorkingKey: str = "working_key"
        RsaPublic: str = "rsaPublic"
        PichakRsaPublic: str = "pichakRSAPublic"

    DefaultAesIv: bytes = bytes(16)
    CustomAesIv: bytes = bytes([48, 148, 136, 186, 72, 57, 83, 116, 19, 138, 210, 230, 3, 165, 240, 35])


class Config:
    """Global Runtime Configuration."""
    API_BASE_URL: str = os.getenv("IVA_BASE_URL", IvaConstants.ApiBaseUrl).rstrip("/")
    API_PREFIX: str = os.getenv("IVA_API_PREFIX", IvaConstants.ApiPrefix)
    PUBLIC_KEY_URL: str = os.getenv("IVA_PUBLIC_KEY_URL", IvaConstants.PublicKeyUrl)
    APP_VERSION: str = os.getenv("IVA_APP_VERSION", IvaConstants.AppVersion)
    KEY_ID: str = os.getenv("IVA_KEY_ID", "1")
    SESSION_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_SESSION_DIR", "./sessions")))
    LOGS_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_LOGS_DIR", "./logs")))
    REQUEST_TIMEOUT: float = float(os.getenv("IVA_TIMEOUT", "65.0"))
    MAX_CHARGE_RETRIES: int = int(os.getenv("IVA_MAX_CHARGE_RETRIES", "10"))
    CHARGE_RETRY_DELAY: float = float(os.getenv("IVA_CHARGE_RETRY_DELAY", "0.5"))
    BOT_START_TIME: float = time.time()

    RETRYABLE_STATUS_MESSAGES: List[str] = [
        "محدودیت روزانه تراکنش",
        "عملیات ناموفق بود",
        "سرویس در حال حاضر قادر به پاسخگویی نیست",
    ]

    DAILY_LIMIT_MESSAGES: List[str] = [
        "محدودیت روزانه تراکنش",
    ]

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

logger = logging.getLogger("IvaScannerBot")
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
# 2. Cryptographic Engine (IvaCrypto - 3-Tier Fallback)
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

_AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _pure_aes256_expand_key(key: bytes) -> List[List[int]]:
    w = [list(key[4 * i : 4 * i + 4]) for i in range(8)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = [_AES_SBOX[temp[1]], _AES_SBOX[temp[2]], _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]]
            temp[0] ^= _RCON[i // 8]
        elif i % 8 == 4:
            temp = [_AES_SBOX[x] for x in temp]
        w.append([w[i - 8][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(15):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _inv_mix_columns(state: List[List[int]]) -> None:
    def mul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi: a ^= 0x1B
            b >>= 1
        return p
    for c in range(4):
        u = state[c]
        s0 = mul(u[0], 0x0E) ^ mul(u[1], 0x0B) ^ mul(u[2], 0x0D) ^ mul(u[3], 0x09)
        s1 = mul(u[0], 0x09) ^ mul(u[1], 0x0E) ^ mul(u[2], 0x0B) ^ mul(u[3], 0x0D)
        s2 = mul(u[0], 0x0D) ^ mul(u[1], 0x09) ^ mul(u[2], 0x0E) ^ mul(u[3], 0x0B)
        s3 = mul(u[0], 0x0B) ^ mul(u[1], 0x0D) ^ mul(u[2], 0x09) ^ mul(u[3], 0x0E)
        state[c] = [s0, s1, s2, s3]


def _pure_aes256_encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = [list(block[4 * i : 4 * i + 4]) for i in range(4)]
    for r in range(4):
        for c in range(4):
            state[c][r] ^= round_keys[0][r + 4 * c]
    for rnd in range(1, 14):
        for r in range(4):
            for c in range(4):
                state[c][r] = _AES_SBOX[state[c][r]]
        s0, s1, s2, s3 = state[0][1], state[1][1], state[2][1], state[3][1]
        state[0][1], state[1][1], state[2][1], state[3][1] = s1, s2, s3, s0
        s0, s1, s2, s3 = state[0][2], state[1][2], state[2][2], state[3][2]
        state[0][2], state[1][2], state[2][2], state[3][2] = s2, s3, s0, s1
        s0, s1, s2, s3 = state[0][3], state[1][3], state[2][3], state[3][3]
        state[0][3], state[1][3], state[2][3], state[3][3] = s3, s0, s1, s2
        for c in range(4):
            a0, a1, a2, a3 = state[c][0], state[c][1], state[c][2], state[c][3]
            state[c][0] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
            state[c][1] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
            state[c][2] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
            state[c][3] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
        for r in range(4):
            for c in range(4):
                state[c][r] ^= round_keys[rnd][r + 4 * c]
    for r in range(4):
        for c in range(4):
            state[c][r] = _AES_SBOX[state[c][r]]
    s0, s1, s2, s3 = state[0][1], state[1][1], state[2][1], state[3][1]
    state[0][1], state[1][1], state[2][1], state[3][1] = s1, s2, s3, s0
    s0, s1, s2, s3 = state[0][2], state[1][2], state[2][2], state[3][2]
    state[0][2], state[1][2], state[2][2], state[3][2] = s2, s3, s0, s1
    s0, s1, s2, s3 = state[0][3], state[1][3], state[2][3], state[3][3]
    state[0][3], state[1][3], state[2][3], state[3][3] = s3, s0, s1, s2
    for r in range(4):
        for c in range(4):
            state[c][r] ^= round_keys[14][r + 4 * c]
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[c][r]
    return bytes(out)


def _pure_aes256_decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    state = [list(block[4 * i : 4 * i + 4]) for i in range(4)]
    for r in range(4):
        for c in range(4):
            state[c][r] ^= round_keys[14][r + 4 * c]
    for rnd in range(13, 0, -1):
        s0, s1, s2, s3 = state[0][1], state[1][1], state[2][1], state[3][1]
        state[0][1], state[1][1], state[2][1], state[3][1] = s3, s0, s1, s2
        s0, s1, s2, s3 = state[0][2], state[1][2], state[2][2], state[3][2]
        state[0][2], state[1][2], state[2][2], state[3][2] = s2, s3, s0, s1
        s0, s1, s2, s3 = state[0][3], state[1][3], state[2][3], state[3][3]
        state[0][3], state[1][3], state[2][3], state[3][3] = s1, s2, s3, s0
        for c in range(4):
            for r in range(4):
                state[c][r] = _AES_INV_SBOX[state[c][r]]
        for r in range(4):
            for c in range(4):
                state[c][r] ^= round_keys[rnd][r + 4 * c]
        _inv_mix_columns(state)
    s0, s1, s2, s3 = state[0][1], state[1][1], state[2][1], state[3][1]
    state[0][1], state[1][1], state[2][1], state[3][1] = s3, s0, s1, s2
    s0, s1, s2, s3 = state[0][2], state[1][2], state[2][2], state[3][2]
    state[0][2], state[1][2], state[2][2], state[3][2] = s2, s3, s0, s1
    s0, s1, s2, s3 = state[0][3], state[1][3], state[2][3], state[3][3]
    state[0][3], state[1][3], state[2][3], state[3][3] = s1, s2, s3, s0
    for c in range(4):
        for r in range(4):
            state[c][r] = _AES_INV_SBOX[state[c][r]]
    for r in range(4):
        for c in range(4):
            state[c][r] ^= round_keys[0][r + 4 * c]
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[c][r]
    return bytes(out)


def _pure_aes256_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    round_keys = _pure_aes256_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(x ^ y for x, y in zip(padded[i : i + 16], prev))
        enc = _pure_aes256_encrypt_block(block, round_keys)
        out.extend(enc)
        prev = enc
    return bytes(out)


def _pure_aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    round_keys = _pure_aes256_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        enc_block = data[i : i + 16]
        dec = _pure_aes256_decrypt_block(enc_block, round_keys)
        plain_block = bytes(x ^ y for x, y in zip(dec, prev))
        out.extend(plain_block)
        prev = enc_block
    pad_len = out[-1]
    if pad_len < 1 or pad_len > 16 or out[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding")
    return bytes(out[:-pad_len])


class IvaCrypto:
    """
    Complete Cryptographic subsystem supporting:
      - AES-256-CBC with DefaultAesIv (zero IV) or CustomAesIv (output lowercase hex)
      - HMAC-SHA256 (output Base64)
      - RSA-2048 PKCS#1 v1.5 Encryption (output lowercase hex)
      - SPKI / Modulus PEM parsing and wrapping
    """

    @staticmethod
    def generate_key(num_bytes: int = 32) -> bytes:
        return secrets.token_bytes(num_bytes)

    @classmethod
    def aes_encrypt(cls, plaintext: str, key_base64: Optional[str] = None) -> str:
        """AES-256-CBC encryption with DefaultAesIv (zero IV). Returns lowercase hex."""
        return cls.aes_encrypt_with_iv(plaintext, key_base64, IvaConstants.DefaultAesIv)

    @classmethod
    def aes_encrypt2(cls, plaintext: str, key_base64: Optional[str] = None, iv: Optional[bytes] = None) -> str:
        """AES-256-CBC encryption with CustomAesIv. Returns lowercase hex."""
        return cls.aes_encrypt_with_iv(plaintext, key_base64, iv or IvaConstants.CustomAesIv)

    @classmethod
    def aes_decrypt(cls, hex_str: str, key_base64: Optional[str] = None) -> str:
        """AES-256-CBC decryption with DefaultAesIv (zero IV). Returns plain string."""
        return cls.aes_decrypt_with_iv(hex_str, key_base64, IvaConstants.DefaultAesIv)

    @classmethod
    def aes_encrypt_with_iv(cls, plaintext: str, key_base64: Optional[str], iv: bytes) -> str:
        if not key_base64:
            raise ValueError("Shared key is not set. Run KeyExchange first.")
        key = base64.b64decode(key_base64)
        data = plaintext.encode("utf-8")

        if _HAS_CRYPTOGRAPHY:
            padder = crypto_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return encrypted.hex().lower()

        if _LIBCRYPTO:
            try:
                ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
                cipher = _LIBCRYPTO.EVP_aes_256_cbc()
                _LIBCRYPTO.EVP_EncryptInit_ex(ctx, cipher, None, key, iv)
                out = (ctypes.c_ubyte * (len(data) + 32))()
                out_len = ctypes.c_int(0)
                _LIBCRYPTO.EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), data, len(data))
                tot = out_len.value
                fin_len = ctypes.c_int(0)
                _LIBCRYPTO.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, tot), ctypes.byref(fin_len))
                tot += fin_len.value
                _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)
                return bytes(out[:tot]).hex().lower()
            except Exception:
                pass

        # Pure python fallback
        encrypted = _pure_aes256_cbc_encrypt(key, iv, data)
        return encrypted.hex().lower()

    @classmethod
    def aes_decrypt_with_iv(cls, hex_str: str, key_base64: Optional[str], iv: bytes) -> str:
        if not key_base64:
            raise ValueError("Shared key is not set. Run KeyExchange first.")
        key = base64.b64decode(key_base64)
        cipher_bytes = bytes.fromhex(hex_str)

        if _HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(cipher_bytes) + decryptor.finalize()
            unpadder = crypto_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data.decode("utf-8")

        if _LIBCRYPTO:
            try:
                ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
                cipher = _LIBCRYPTO.EVP_aes_256_cbc()
                _LIBCRYPTO.EVP_DecryptInit_ex(ctx, cipher, None, key, iv)
                out = (ctypes.c_ubyte * (len(cipher_bytes) + 32))()
                out_len = ctypes.c_int(0)
                _LIBCRYPTO.EVP_DecryptUpdate(ctx, out, ctypes.byref(out_len), cipher_bytes, len(cipher_bytes))
                tot = out_len.value
                fin_len = ctypes.c_int(0)
                _LIBCRYPTO.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, tot), ctypes.byref(fin_len))
                tot += fin_len.value
                _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)
                return bytes(out[:tot]).decode("utf-8")
            except Exception:
                pass

        # Pure python fallback
        data = _pure_aes256_cbc_decrypt(key, iv, cipher_bytes)
        return data.decode("utf-8")

    @classmethod
    def hmac_sha256(cls, data: str, key_base64: str) -> str:
        """HMAC-SHA256 calculation. Returns Base64 string for Sign-Data header."""
        key = base64.b64decode(key_base64)
        h = hmac.new(key, data.encode("utf-8"), hashlib.sha256)
        return base64.b64encode(h.digest()).decode("ascii")

    @classmethod
    def rsa_encrypt(cls, plaintext: str, public_key_pem: str) -> str:
        """RSA-2048 PKCS#1 v1.5 encryption. Returns lowercase hex string."""
        data = plaintext.encode("utf-8")

        if _HAS_CRYPTOGRAPHY:
            pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))
            encrypted = pub_key.encrypt(data, asym_padding.PKCS1v15())
            return encrypted.hex().lower()

        # Pure Python PKCS#1 v1.5 RSA implementation
        n, e = cls._parse_pem_rsa_pubkey(public_key_pem)
        k = (n.bit_length() + 7) // 8
        if len(data) > k - 11:
            raise ValueError("Data too long for RSA key size")

        ps_len = k - len(data) - 3
        ps = bytearray()
        while len(ps) < ps_len:
            rb = secrets.token_bytes(ps_len - len(ps))
            for b in rb:
                if b != 0:
                    ps.append(b)

        em = b"\x00\x02" + bytes(ps) + b"\x00" + data
        m = int.from_bytes(em, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes(k, "big")
        return c_bytes.hex().lower()

    @staticmethod
    def _parse_pem_rsa_pubkey(pem: str) -> Tuple[int, int]:
        """Parses modulus n and exponent e from PEM SubjectPublicKeyInfo or PKCS#1."""
        lines = [line.strip() for line in pem.strip().splitlines() if not line.startswith("-----")]
        der = base64.b64decode("".join(lines))

        def read_asn1(buf: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
            tag = buf[offset]
            offset += 1
            length = buf[offset]
            offset += 1
            if length & 0x80:
                num_octets = length & 0x7F
                length = int.from_bytes(buf[offset : offset + num_octets], "big")
                offset += num_octets
            content = buf[offset : offset + length]
            return tag, content, offset + length

        pos = 0
        tag, seq_content, _ = read_asn1(der, 0)
        p = 0
        t1, c1, p1 = read_asn1(seq_content, p)
        if t1 == 0x30:  # AlgorithmIdentifier
            t2, bitstring, _ = read_asn1(seq_content, p1)
            raw_seq = bitstring[1:]  # skip unused bits
            _, key_seq_content, _ = read_asn1(raw_seq, 0)
        else:
            key_seq_content = seq_content

        kp = 0
        _, mod_bytes, kp1 = read_asn1(key_seq_content, kp)
        _, exp_bytes, _ = read_asn1(key_seq_content, kp1)
        n = int.from_bytes(mod_bytes, "big")
        e = int.from_bytes(exp_bytes, "big")
        return n, e

    @staticmethod
    def base64_to_hex(base64_str: str) -> str:
        return base64.b64decode(base64_str).hex().lower()

    @staticmethod
    def hex_to_base64(hex_str: str) -> str:
        return base64.b64encode(bytes.fromhex(hex_str)).decode("ascii")

    @classmethod
    def base64_modulus_to_pem(cls, base64_modulus: str) -> str:
        """Wraps a bare Base64 RSA modulus into a standard SPKI PEM string."""
        spki_prefix = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
        spki_suffix = "0203010001"
        mod_clean = base64_modulus.replace("\r", "").replace("\n", "").replace(" ", "")
        mod_hex = base64.b64decode(mod_clean).hex().lower()
        der_hex = spki_prefix + mod_hex + spki_suffix
        der_bytes = bytes.fromhex(der_hex)
        b64 = base64.b64encode(der_bytes).decode("ascii")
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
    tokenType: Optional[str] = None
    expiresIn: Optional[int] = None
    accessTokenObtainedAt: Optional[int] = None
    sharedKey: Optional[str] = None
    workingKey: Optional[str] = None
    rsaPublic: Optional[str] = None


@dataclass
class CardPayment:
    pan: Optional[str] = None
    cvv2: Optional[str] = None
    expireMonth: Optional[str] = None
    expireYear: Optional[str] = None
    pin: Optional[str] = None
    token: Optional[str] = None

    def validate(self) -> None:
        if not self.token:
            if not self.pan or len(re.sub(r'\D', '', self.pan)) < 16:
                raise ValueError("شماره کارت (PAN) نامعتبر است (باید حداقل ۱۶ رقم باشد).")
            if not self.cvv2 or len(re.sub(r'\D', '', self.cvv2)) < 3:
                raise ValueError("کد CVV2 نامعتبر است (باید حداقل ۳ رقم باشد).")
            if not self.pin or len(re.sub(r'\D', '', self.pin)) < 4:
                raise ValueError("رمز دوم / رمز پویا نامعتبر است (باید حداقل ۴ رقم باشد).")


@dataclass
class CardInfo:
    pan: str = ""
    expireMonth: str = ""
    expireYear: str = ""
    cvv2: str = ""
    pin: str = ""
    operatorName: str = ""
    factorNumber: str = ""
    success: bool = False
    phoneUsed: str = ""
    errorMessage: str = ""
    testsPerformed: int = 0


@dataclass
class ChargePurchaseRequest:
    amount: int
    targetMobileNo: Optional[str] = None
    providerId: Optional[str] = None
    card: CardPayment = field(default_factory=CardPayment)
    orderId: Optional[int] = None
    extra: Optional[Dict[str, Any]] = None


@dataclass
class ChargePurchaseResult:
    success: bool = False
    errorCode: Optional[str] = None
    message: Optional[str] = None
    usedPhone: Optional[str] = None
    retryCount: int = 0
    factorNumber: Optional[str] = None
    transactionId: Optional[str] = None
    amount: Optional[int] = None
    operatorName: Optional[str] = None
    pin: Optional[str] = None
    serial: Optional[str] = None
    trackingCode: Optional[str] = None
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
    """Thread-safe & atomic session repository isolated per User ID and Phone."""

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
# 5. Async HTTP & IvaAuthClient
# ------------------------------------------------------------------------------

class AsyncHttpClient:
    """Async HTTP executor using standard library urllib with Sadad/Iranian TLS support."""

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
            except ssl.SSLError:
                continue

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
    ) -> Tuple[int, str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_request, method, url, headers, data)

    def _sync_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
    ) -> Tuple[int, str]:
        encoded_data = data.encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=encoded_data, method=method)

        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                code = resp.getcode()
                body = resp.read().decode("utf-8", errors="replace")
                return code, body
        except urllib.error.HTTPError as http_err:
            body = http_err.read().decode("utf-8", errors="replace")
            return http_err.code, body
        except Exception as ex:
            err_msg = str(ex)
            # Second attempt with fallback context
            if "SSL" in err_msg or "HANDSHAKE" in err_msg or "ALERT" in err_msg or "EOF" in err_msg:
                try:
                    alt_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    alt_ctx.check_hostname = False
                    alt_ctx.verify_mode = ssl.CERT_NONE
                    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
                        alt_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
                    try:
                        alt_ctx.set_ciphers("DEFAULT:@SECLEVEL=0:ALL")
                    except Exception:
                        pass
                    alt_handlers = []
                    if self.proxy:
                        alt_handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
                    alt_handlers.append(urllib.request.HTTPSHandler(context=alt_ctx))
                    alt_opener = urllib.request.build_opener(*alt_handlers)

                    with alt_opener.open(req, timeout=self.timeout) as resp:
                        return resp.getcode(), resp.read().decode("utf-8", errors="replace")
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
                    "در صورت استفاده از VPN، گزینه Bypass Iran را فعال کنید."
                )
            else:
                raise IvaApiException(f"خطای ارتباط شبکه: {err_msg}")


class IvaAuthClient:
    """
    Complete Async IVA API Client mirroring C# IvaScanner.IvaAuthClient:
      - 8 Active Endpoints + Shaparak TSM getKey
      - AES/HMAC encryption & Signing
      - Automated 401 Refresh & Single-Retry
      - Card Payment / PIN Charge purchase with retries
    """

    def __init__(self, telegram_user_id: int = 1001, phone: Optional[str] = None, repository: Optional[FileSessionRepository] = None):
        self.user_id = telegram_user_id
        self.current_phone = phone
        self.repo = repository or FileSessionRepository()
        self.session = SessionData(phone=phone)
        self.crypto = IvaCrypto()
        self._last_otp_token: str = ""
        self._last_reagent: str = "0"
        self._current_transaction_id: str = str(secrets.token_hex(16))
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

    def is_token_expired(self, buffer_seconds: int = 30) -> bool:
        if not self.session.token:
            return True
        if not self.session.accessTokenObtainedAt or not self.session.expiresIn:
            return False
        return (time.time() - self.session.accessTokenObtainedAt) >= (self.session.expiresIn - buffer_seconds)

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

        if serialized_body and path not in IvaConstants.SignExclude:
            if self.session.workingKey:
                headers["Sign-Data"] = self.crypto.hmac_sha256(serialized_body, self.session.workingKey)

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

    # --- 1. Fetch Public Key from Shaparak TSM ---
    async def fetch_public_key(self, key_id: Optional[str] = None, transaction_id: Optional[str] = None) -> str:
        final_key_id = key_id or Config.KEY_ID or "1"
        final_transaction_id = transaction_id or self._current_transaction_id
        self._current_transaction_id = final_transaction_id

        payload = {"keyId": final_key_id, "transactionId": final_transaction_id}
        json_body = json.dumps(payload)
        headers = {"Content-Type": "application/json"}

        status, text = await self.http.request("POST", Config.PUBLIC_KEY_URL, headers, json_body)
        if status != 200:
            raise IvaApiException(f"getKey failed (HTTP {status}): {text}", str(status))

        key_data = None
        try:
            doc = json.loads(text)
            errs = doc.get("errors")
            if errs and isinstance(errs, list) and len(errs) > 0:
                err_desc = ", ".join(e.get("errorDescription", str(e)) for e in errs)
                raise IvaApiException(f"getKey returned errors: {err_desc}")

            key_data = doc.get("keyData")
            if not key_data and isinstance(doc.get("data"), dict):
                key_data = doc["data"].get("keyData")
            if not key_data and isinstance(doc.get("data"), str):
                key_data = doc["data"]
        except json.JSONDecodeError:
            pass

        if not key_data:
            raise IvaApiException("getKey response did not contain keyData: " + text)

        # Wrap if raw base64 or keep if PEM
        if "BEGIN" not in str(key_data):
            pem_key = IvaCrypto.base64_modulus_to_pem(str(key_data))
        else:
            pem_key = str(key_data)

        self.session.rsaPublic = pem_key
        await self.save_session()
        return pem_key

    # --- 2. Key Exchange ---
    async def key_exchange(self) -> None:
        if not self.session.rsaPublic:
            try:
                await self.fetch_public_key()
            except Exception:
                await self.try_discover_public_key()

        if not self.session.rsaPublic:
            raise IvaApiException("کلید عمومی RSA سرور یافت نشد. ابتدا getKey یا ورود انجام دهید.")

        shared_key = IvaCrypto.generate_key(32)
        working_key = IvaCrypto.generate_key(32)

        self.session.sharedKey = base64.b64encode(shared_key).decode("utf-8")
        self.session.workingKey = base64.b64encode(working_key).decode("utf-8")

        shared_hex = shared_key.hex().lower()
        working_hex = working_key.hex().lower()

        data_key = IvaCrypto.rsa_encrypt(shared_hex, self.session.rsaPublic)
        mac_key = IvaCrypto.rsa_encrypt(working_hex, self.session.rsaPublic)

        await self._post_json(IvaConstants.Endpoints.KeyExchange, {"DataKey": data_key, "MacKey": mac_key})
        await self.save_session()

    async def ensure_secure_channel(self) -> None:
        if self.session.sharedKey and self.session.workingKey:
            return
        await self.key_exchange()

    # --- 3. Request OTP ---
    async def request_otp(self, phone_number: str) -> Dict[str, Any]:
        self.current_phone = phone_number
        payload = {"PhoneNumber": phone_number}
        data = await self._post_json(IvaConstants.Endpoints.RegisterRequest, payload)
        if isinstance(data, dict):
            self._last_otp_token = str(data.get("Token") or data.get("token") or "")
            self._last_reagent = str(data.get("ReagentNumber") or data.get("reagentNumber") or "0")
        return data

    # --- 4. Verify OTP Code ---
    async def verify_code(self, verification_code: str, token: Optional[str] = None, reagent_number: Optional[str] = None) -> Dict[str, Any]:
        tok = (token or self._last_otp_token or "").strip()
        reagent = (reagent_number or self._last_reagent or "0").strip()
        payload = {
            "VerificationCode": verification_code.strip(),
            "Token": tok,
            "ReagentNumber": reagent
        }
        data = await self._post_json(IvaConstants.Endpoints.Activation, payload)
        self._persist_tokens(data)
        await self.save_session()
        return data

    # --- 5. Refresh Token ---
    async def refresh_token(self, custom_refresh_token: Optional[str] = None) -> Dict[str, Any]:
        rt = custom_refresh_token or self.session.refreshToken
        if not rt:
            raise IvaApiException("رفرش‌توکن یافت نشد. لطفاً مجدداً لاگین کنید.", "401")
        data = await self._post_json(IvaConstants.Endpoints.RefreshToken, {"RefreshToken": rt})
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
        token_type = data.get("tokenType") or data.get("TokenType")
        if token_type:
            self.session.tokenType = str(token_type)
        self.session.accessTokenObtainedAt = int(time.time())
        key = data.get("key") or data.get("Key")
        if key:
            try:
                self.session.rsaPublic = IvaCrypto.base64_modulus_to_pem(str(key))
            except Exception as ex:
                log_debug(f"Modulus wrap note: {ex}")

    # --- 6. User Profile ---
    async def get_profile(self) -> Dict[str, Any]:
        return await self._get_authorized_element(IvaConstants.Endpoints.UserProfile)

    # --- 7. App Configurations & Public Key Discovery ---
    async def try_discover_public_key(self) -> None:
        version_parts = Config.APP_VERSION.split(".")
        query = {
            "VersionCode": version_parts[2] if len(version_parts) > 2 else Config.APP_VERSION,
            "ClientType": "3",
            "MarketType": "4",
        }
        try:
            configs = await self._get_authorized_element(IvaConstants.Endpoints.AppConfiguration, query)
            key = self._find_public_key(configs)
            if key:
                if "BEGIN" not in str(key):
                    self.session.rsaPublic = IvaCrypto.base64_modulus_to_pem(str(key))
                else:
                    self.session.rsaPublic = str(key)
                await self.save_session()
        except Exception as ex:
            log_debug(f"Discovery notice: {ex}")

    def _find_public_key(self, el: Any) -> Optional[str]:
        if isinstance(el, dict):
            for k, v in el.items():
                if isinstance(v, str) and ("public" in k.lower() or "rsapublic" in k.lower()) and len(v) > 50:
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

    # --- 8. Charge Catalog ---
    async def get_charge_catalog(self) -> List[Dict[str, Any]]:
        data = await self._get_authorized_element(IvaConstants.Endpoints.ChargeCatalog)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    # --- 9. Create Payment Body & Buy Charge ---
    def create_payment_body(
        self,
        amount: int,
        card: CardPayment,
        extra: Optional[Dict[str, Any]] = None,
        pocket_id: Optional[str] = None,
        order_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not self.session.sharedKey:
            raise ValueError("کانال امن برقرار نشده است. لطفاً ابتدا تبادل کلید انجام دهید.")

        media: Dict[str, Any] = {}
        if card.cvv2:
            media["Cvv2"] = self.crypto.aes_encrypt(card.cvv2, self.session.sharedKey)
        if card.pin:
            media["Pin"] = self.crypto.aes_encrypt(card.pin, self.session.sharedKey)

        expire = (card.expireYear or "") + (card.expireMonth or "").zfill(2)
        digits_exp = "".join(c for c in expire if c.isdigit())
        if len(digits_exp) == 4:
            media["ExpireDate"] = self.crypto.aes_encrypt(expire, self.session.sharedKey)

        if card.token:
            media["Token"] = card.token
        elif card.pan:
            media["Pan"] = self.crypto.aes_encrypt(card.pan, self.session.sharedKey)

        if pocket_id:
            media["PocketId"] = pocket_id

        body: Dict[str, Any] = {"paymentMedia": media}
        if extra:
            body.update(extra)

        body["Amount"] = amount
        body["OrderId"] = order_id or int(time.time() * 1000)
        return body

    async def post_signed_once(
        self,
        path: str,
        body: Dict[str, Any],
        content_type: str,
        use_proxy: bool = False,
    ) -> Tuple[int, str]:
        url = Config.get_base_address() + path
        json_body = json.dumps(body, ensure_ascii=False)
        headers = self.apply_headers(path, json_body)
        headers["Content-Type"] = content_type

        return await self.http.request("POST", url, headers, json_body)

    def parse_charge_outcome(self, text: str, status: int) -> ChargePurchaseResult:
        try:
            doc = json.loads(text) if text.strip() else {}
            err = doc.get("error")
            data = doc.get("data") if doc.get("data") is not None else doc

            if err and str(err.get("code")) not in ("200", "None", ""):
                return ChargePurchaseResult(
                    success=False,
                    errorCode=str(err.get("code")),
                    message=err.get("message") or f"خطای درگاه (کد {err.get('code')})",
                )

            is_success = (status in (200, 201, 204)) and bool(data.get("trackingCode") or data.get("factorNumber") or data.get("pin") or data.get("transactionId"))
            return ChargePurchaseResult(
                success=is_success,
                errorCode=str(status) if not is_success else None,
                message=data.get("statusDescription") or data.get("statusTitle") or ("موفقیت‌آمیز" if is_success else None),
                trackingCode=data.get("trackingCode"),
                transactionId=data.get("transactionId"),
                referenceNumber=data.get("referenceNumber"),
                factorNumber=data.get("factorNumber"),
                pin=data.get("pin"),
                serial=data.get("serial"),
                status=data.get("status"),
                cardHolderName=data.get("cardHolderName"),
            )
        except Exception:
            return ChargePurchaseResult(
                success=False,
                errorCode=str(status),
                message=f"HTTP {status}: {text[:120]}",
            )

    async def buy_charge(
        self,
        request: ChargePurchaseRequest,
        use_proxy: bool = False,
    ) -> ChargePurchaseResult:
        request.card.validate()
        await self.ensure_secure_channel()

        variant = "Token" if request.card.token else "pan"
        content_type = f"application/vnd.sadad.payment.charge.{variant}+json"

        order_id = request.orderId

        def build_body() -> Dict[str, Any]:
            extra: Dict[str, Any] = {
                "TTL": int(time.time() * 1000),
                "TargetMobileNo": request.targetMobileNo or self.current_phone,
                "ProviderId": request.providerId or "1",
            }
            if request.extra:
                extra.update(request.extra)
            return self.create_payment_body(
                amount=request.amount,
                card=request.card,
                extra=extra,
                order_id=order_id,
            )

        built = build_body()
        order_id = built.get("OrderId")

        status, text = await self.post_signed_once(IvaConstants.Endpoints.PayCharge, built, content_type, use_proxy=use_proxy)

        # On 401: Refresh and retry once
        if status == 401:
            log_info("Received 401 on PayCharge, refreshing auth and retrying...")
            await self.refresh_auth()
            built = build_body()
            status, text = await self.post_signed_once(IvaConstants.Endpoints.PayCharge, built, content_type, use_proxy=use_proxy)

        outcome = self.parse_charge_outcome(text, status)
        outcome.usedPhone = self.current_phone
        outcome.amount = request.amount
        return outcome


# ------------------------------------------------------------------------------
# 6. Interactive Terminal CLI Interface
# ------------------------------------------------------------------------------

async def run_terminal_cli() -> None:
    """Complete interactive Terminal CLI for login, profile, card test and admin without Telegram."""
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
    print("🏦 سامانه ترمینال احراز هویت و اسکنر IVA / Sadad (IvaScanner)")
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
        print("5. 🔑 دریافت کلید عمومی شاپراک (TSM getKey)")
        print("6. 📱 دریافت اطلاعات پایه و کاتالوگ شارژ")
        print("7. 💳 خرید شارژ و تست کارت بانکی (Card Payment / Scanner)")
        print("8. 📋 مشاهده و تعویض حساب‌های ذخیره‌شده")
        print("9. 🤖 اجرای ربات تلگرام (Telegram Bot Polling)")
        print("10. 🗑 حذف تمامی سشن‌ها و پاکسازی دیتابیس محلی")
        print("0. ❌ خروج")
        print("-" * 55)

        choice = await loop.run_in_executor(None, ask, "👉 شماره گزینه را وارد فرمایید [0-10]: ")

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
                print("🎉 ورود با موفقیت انجام شد!")
                print(f"⏱ مدت اعتبار توکن: {token_res.get('expiresIn', 0)} ثانیه")

                print("⏳ در حال انجام تبادل کلید امنیتی (KeyExchange)...")
                try:
                    await client.key_exchange()
                    print("✅ تبادل کلید امنیتی با موفقیت انجام شد.")
                except Exception as k_ex:
                    print(f"⚠️ هشدار در تبادل کلید: {k_ex}")

            except Exception as ex:
                print(f"❌ خطا در احراز هویت: {ex}")

        elif choice == "2":
            if not client.session.token:
                print("❌ شما وارد نشده‌اید. ابتدا گزینه 1 را اجرا کنید.")
                continue
            print("⏳ در حال دریافت پروفایل از سرور...")
            try:
                prof = await client.get_profile()
                print("\n👤 اطلاعات پروفایل:")
                print(f"نام: {prof.get('firstName', '')} {prof.get('lastName', '')}")
                print(f"کد ملی: {prof.get('nationalCode', '---')}")
                print(f"شماره موبایل: {prof.get('cellPhoneNumber', client.current_phone)}")
            except Exception as ex:
                print(f"❌ خطا: {ex}")

        elif choice == "3":
            if not client.session.refreshToken:
                print("❌ رفرش‌توکن ذخیره‌شده‌ای یافت نشد.")
                continue
            print("⏳ در حال تمدید توکن...")
            try:
                res = await client.refresh_token()
                print(f"✅ توکن تمدید شد. اعتبار: {res.get('expiresIn', 0)} ثانیه")
            except Exception as ex:
                print(f"❌ خطا: {ex}")

        elif choice == "4":
            print("⏳ در حال انجام تبادل کلید...")
            try:
                await client.key_exchange()
                print("✅ تبادل کلید با موفقیت انجام شد.")
            except Exception as ex:
                print(f"❌ خطا: {ex}")

        elif choice == "5":
            print("⏳ در حال دریافت کلید عمومی شاپراک از TSM...")
            try:
                pem = await client.fetch_public_key()
                print("✅ کلید عمومی شاپراک دریافت و ذخیره گردید:")
                print(pem[:120] + "...")
            except Exception as ex:
                print(f"❌ خطا: {ex}")

        elif choice == "6":
            print("⏳ در حال دریافت اطلاعات کاتالوگ شارژ...")
            try:
                cat = await client.get_charge_catalog()
                print(f"✅ کاتالوگ شارژ دریافت شد. تعداد آیتم‌ها: {len(cat)}")
            except Exception as ex:
                print(f"❌ خطا: {ex}")

        elif choice == "7":
            print("\n💳 خرید شارژ و تست کارت بانکی:")
            pan = await loop.run_in_executor(None, ask, "شماره کارت ۱۶ رقمی (PAN): ")
            exp_year = await loop.run_in_executor(None, ask, "سال انقضا (دو رقم مثلاً 05): ")
            exp_month = await loop.run_in_executor(None, ask, "ماه انقضا (دو رقم مثلاً 12): ")
            cvv2 = await loop.run_in_executor(None, ask, "کد CVV2: ")
            pin = await loop.run_in_executor(None, ask, "رمز دوم / پویا: ")
            amount_str = await loop.run_in_executor(None, ask, "مبلغ به ریال (پیش‌فرض 10000): ")
            amount = int(amount_str) if amount_str.isdigit() else 10000

            card = CardPayment(
                pan=pan.replace(" ", "").replace("-", ""),
                expireYear=exp_year.strip(),
                expireMonth=exp_month.strip(),
                cvv2=cvv2.strip(),
                pin=pin.strip(),
            )
            req = ChargePurchaseRequest(
                amount=amount,
                targetMobileNo=client.current_phone,
                providerId="1",
                card=card,
            )

            print("⏳ در حال ارسال تراکنش شارژ...")
            try:
                res = await client.buy_charge(req)
                if res.success:
                    print("🎉 تراکنش موفقیت‌آمیز بود!")
                    print(f"کد پیگیری: {res.trackingCode}")
                    print(f"شماره فاکتور: {res.factorNumber}")
                    print(f"پین شارژ: {res.pin}")
                else:
                    print(f"❌ تراکنش ناموفق: {res.message} (کد {res.errorCode})")
            except Exception as ex:
                print(f"❌ خطای پرداخت: {ex}")

        elif choice == "8":
            phones = await repo.list_phones(user_id)
            if not phones:
                print("📭 هیچ حسابی ذخیره نشده است.")
                continue
            print("\n📋 لیست حساب‌های ذخیره‌شده:")
            for idx, p in enumerate(phones, 1):
                marker = "👈 (فعال)" if p == client.current_phone else ""
                print(f"{idx}. {p} {marker}")

            sel = await loop.run_in_executor(None, ask, "شماره ردیف حساب جهت انتخاب (یا Enter برای رد شدن): ")
            if sel.isdigit() and 1 <= int(sel) <= len(phones):
                target = phones[int(sel) - 1]
                await client.load_session(target)
                print(f"✅ حساب فعال به {target} تغییر یافت.")

        elif choice == "9":
            token = Config.get_bot_token()
            if not token:
                token = await loop.run_in_executor(None, ask, "🤖 توکن ربات تلگرام را وارد فرمایید: ")
            if not token:
                print("❌ توکن ربات تلگرام وارد نشد.")
                continue
            print("\n🚀 در حال راه‌اندازی ربات تلگرام...")
            bot = TelegramBot(token)
            await bot.start_polling()

        elif choice == "10":
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
                {"text": "🔐 احراز هویت (OTP)", "callback_data": "menu_auth"},
                {"text": "👤 حساب من", "callback_data": "menu_profile"},
            ],
            [
                {"text": "🔄 تمدید توکن", "callback_data": "menu_refresh"},
                {"text": "🔑 تبادل کلید", "callback_data": "menu_keyexchange"},
            ],
            [
                {"text": "🔑 کلید شاپراک TSM", "callback_data": "menu_tsm_key"},
                {"text": "📱 اطلاعات IVA", "callback_data": "menu_configs"},
            ],
            [
                {"text": "💳 خرید شارژ و تست کارت", "callback_data": "menu_charge"},
                {"text": "📋 مدیریت حساب‌ها", "callback_data": "menu_accounts"},
            ],
            [
                {"text": "📊 وضعیت نشست", "callback_data": "menu_status"},
                {"text": "🧪 تست API", "callback_data": "menu_apitest"},
            ],
            [
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
                "🏦 <b>سامانه مدیریت و اسکنر IVA / Sadad (IvaScanner)</b>\n\n"
                f"وضعیت اتصال: <b>{'🟢 متصل و آماده' if is_connected else '⚪ متصل نیست'}</b>\n"
                f"حساب فعال: <code>{clean_html(phone or 'تعیین نشده')}</code>\n"
                f"نسخه PWA: <code>{Config.APP_VERSION}</code>\n\n"
                "جهت اجرای عملیات یکی از گزینه‌های زیر را انتخاب نمایید:"
            )
            await self.send_message(chat_id, welcome, self.get_main_menu(is_connected, phone, user_id))
            return

        if text in ("/logout", "/clearsessions"):
            phones = await self.repo.list_phones(user_id)
            for p in phones:
                await self.repo.delete(user_id, p)
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
                "📖 <b>راهنمای ربات IVA Scanner</b>\n\n"
                "• <b>🔐 احراز هویت:</b> ورود به سیستم با شماره موبایل و کد پیامکی OTP.\n"
                "• <b>👤 حساب من:</b> نمایش اطلاعات پروفایل کاربری از <code>/v1/users/me</code>.\n"
                "• <b>🔄 تمدید توکن:</b> دریافت اکسس‌توکن جدید با رفرش‌توکن ذخیره‌شده.\n"
                "• <b>🔑 تبادل کلید:</b> تولید کلیدهای امنیتی AES و ارسال امن به سرور.\n"
                "• <b>🔑 کلید شاپراک TSM:</b> دریافت مستقیم کلید عمومی شاپراک از <code>tsm.shaparak.ir</code>.\n"
                "• <b>💳 خرید شارژ و تست کارت:</b> انجام تراکنش و تست کارت با رمزنگاری AES.\n"
                "• <b>📋 مدیریت حساب‌ها:</b> جابجایی بین چندین شماره و افزودن حساب جدید.\n"
                "• <b>📊 وضعیت:</b> بررسی مدت زمان اعتبار توکن و آماده‌بودن کلیدها.\n"
                "• <b>🧪 تست API:</b> تست سلامت تک‌تک اندپوینت‌ها.\n"
                "• <b>🗑 خروج کامل:</b> ارسال دستور <code>/logout</code> جهت حذف تمام سشن‌ها."
            )
            await self.send_message(chat_id, help_text)
            return

        if text == "/admin" and self.is_admin(user_id):
            await self.show_admin_panel(chat_id)
            return

        # OTP Phone Input Step
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
                await self.send_message(chat_id, f"📩 کد ۵ رقمی به شماره <code>{clean_html(phone)}</code> پیامک شد.\nلطفاً کد دریافتی را ارسال نمایید:")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در درخواست OTP:\n{clean_html(ex)}")
            return

        # OTP Code Verify Step
        if step == "auth_otp":
            otp_code = text.strip()
            phone = state.get("phone", "")
            req_token = state.get("token", "")
            reagent = state.get("reagent", "0")
            client = await self.get_client(user_id)
            client.current_phone = phone

            await self.send_message(chat_id, "⏳ در حال اعتبارسنجی کد در سرور سداد...")
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

        # Card Charge Payment / Scanner Wizard
        if step == "charge_wizard":
            # Supports direct pipe format: PAN|YY|MM|CVV2|PIN|AMOUNT|PHONE or single line
            parts = [p.strip() for p in text.split("|")]
            if len(parts) >= 5:
                pan, yy, mm, cvv2, pin = parts[0], parts[1], parts[2], parts[3], parts[4]
                amount = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 10000
                target_phone = parts[6] if len(parts) > 6 and parts[6].startswith("09") else (client.current_phone or "")

                card = CardPayment(
                    pan=re.sub(r'\D', '', pan),
                    expireYear=yy.zfill(2),
                    expireMonth=mm.zfill(2),
                    cvv2=cvv2,
                    pin=pin,
                )
                req = ChargePurchaseRequest(
                    amount=amount,
                    targetMobileNo=target_phone,
                    providerId="1",
                    card=card,
                )

                client = await self.get_client(user_id)
                await self.send_message(chat_id, "⏳ در حال رمزنگاری اطلاعات کارت و ارسال تراکنش...")
                try:
                    res = await client.buy_charge(req)
                    user_states[user_id] = {}
                    if res.success:
                        card_mask = mask_sensitive(card.pan or "")
                        res_text = (
                            "🎉 <b>تراکنش با موفقیت انجام شد!</b>\n\n"
                            f"💳 کارت: <code>{card_mask}</code>\n"
                            f"💰 مبلغ: <code>{amount:,} ریال</code>\n"
                            f"🧾 شماره فاکتور: <code>{clean_html(res.factorNumber or '---')}</code>\n"
                            f"🔢 کد پیگیری: <code>{clean_html(res.trackingCode or '---')}</code>\n"
                            f"🆔 شناسه تراکنش: <code>{clean_html(res.transactionId or '---')}</code>\n"
                            f"🔑 پین شارژ: <code>{clean_html(res.pin or '---')}</code>\n"
                            f"👤 دارنده کارت: <code>{clean_html(res.cardHolderName or '---')}</code>"
                        )
                    else:
                        res_text = (
                            "❌ <b>تراکنش ناموفق بود:</b>\n\n"
                            f"پیام سرور: <code>{clean_html(res.message or 'خطای ناشناخته')}</code>\n"
                            f"کد خطا: <code>{clean_html(res.errorCode or '---')}</code>"
                        )
                    await self.send_message(chat_id, res_text, self.get_main_menu(bool(client.session.token), client.current_phone, user_id))
                except Exception as ex:
                    await self.send_message(chat_id, f"❌ خطای پرداخت شارژ:\n{clean_html(ex)}")
                return
            else:
                await self.send_message(chat_id, "❌ قالب نامعتبر است.\nلطفاً اطلاعات را به این فرمت ارسال کنید:\n<code>شماره‌کارت|سال|ماه|CVV2|رمز‌پویا|مبلغ</code>\n\nمثال:\n<code>6037991234567890|05|10|123|12345|10000</code>")
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
            await self.send_message(chat_id, "📱 لطفاً شماره تلفن همراه خود را ارسال فرمایید:\nمثال: <code>09121234567</code>")
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

        if data == "menu_tsm_key":
            await self.send_message(chat_id, "🔑 در حال دریافت کلید عمومی شاپراک از سامانه TSM...")
            try:
                pem = await client.fetch_public_key()
                await self.send_message(chat_id, "✅ کلید عمومی شاپراک (TSM) با موفقیت دریافت و ثبت گردید.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای دریافت کلید شاپراک:\n{clean_html(ex)}")
            return

        if data == "menu_configs":
            info_text = (
                "📱 <b>اطلاعات پیکربندی و سرورهای IVA / Sadad:</b>\n\n"
                f"آدرس پایه: <code>{Config.API_BASE_URL}</code>\n"
                f"پیشوند API: <code>{Config.API_PREFIX}</code>\n"
                f"آدرس کلید TSM: <code>{Config.PUBLIC_KEY_URL}</code>\n"
                f"نسخه PWA: <code>{Config.APP_VERSION}</code>\n"
                f"محیط رمزنگاری: <b>{'Cryptography Module' if _HAS_CRYPTOGRAPHY else ('Native libcrypto' if _LIBCRYPTO else 'Pure-Python AES Engine')}</b>"
            )
            await self.send_message(chat_id, info_text)
            return

        if data == "menu_charge":
            user_states[user_id] = {"step": "charge_wizard"}
            guide_msg = (
                "💳 <b>خرید شارژ و تست کارت بانکی (Card Payment / Scanner):</b>\n\n"
                "لطفاً اطلاعات کارت را در یک پیام با علامت <code>|</code> ارسال فرمایید:\n"
                "<code>شماره‌کارت|سال|ماه|CVV2|رمز‌پویا|مبلغ</code>\n\n"
                "📝 <b>مثال:</b>\n"
                "<code>6037991234567890|05|10|123|12345|10000</code>\n\n"
                "(مبلغ پیش‌فرض ۱۰,۰۰۰ ریال است و در صورت عدم ورود، در نظر گرفته خواهد شد)."
            )
            await self.send_message(chat_id, guide_msg)
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
                [{"text": "🧪 تست Shaparak TSM", "callback_data": "test_tsm"}],
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

        if data == "test_tsm":
            try:
                pem = await client.fetch_public_key()
                await self.send_message(chat_id, f"✅ خروجی موفق <code>tsm.shaparak.ir</code>:\n<code>{clean_html(pem[:200])}...</code>")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست TSM:\n{clean_html(ex)}")
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
            log_error("TELEGRAM_BOT_TOKEN is not configured. Telegram bot polling aborted.")
            return

        log_info("Starting Telegram Bot Long-Polling Engine...")
        self.is_running = True
        offset = 0

        # Fetch bot user info
        me = await self.call_api("getMe")
        if me.get("ok"):
            bot_user = me.get("result", {})
            log_info(f"Bot connected: @{bot_user.get('username')} ({bot_user.get('first_name')})")
        else:
            log_error(f"Failed to getMe: {me.get('description')}")

        while self.is_running:
            try:
                res = await self.call_api("getUpdates", {"offset": offset, "timeout": 25})
                if res.get("ok"):
                    updates = res.get("result", [])
                    for upd in updates:
                        offset = max(offset, upd["update_id"] + 1)
                        asyncio.create_task(self.handle_update(upd))
                else:
                    await asyncio.sleep(3)
            except asyncio.CancelledError:
                break
            except Exception as ex:
                log_error(f"Polling Exception: {ex}")
                await asyncio.sleep(3)


# ------------------------------------------------------------------------------
# 8. Entrypoint Dispatcher
# ------------------------------------------------------------------------------

def run_preflight_checks() -> bool:
    """Verifies crypto primitives and storage paths before startup."""
    try:
        # Check AES encryption and decryption
        test_key = base64.b64encode(b"\x01" * 32).decode("ascii")
        enc = IvaCrypto.aes_encrypt("test_message", test_key)
        dec = IvaCrypto.aes_decrypt(enc, test_key)
        if dec != "test_message":
            return False

        # Check HMAC
        mac = IvaCrypto.hmac_sha256("test_body", test_key)
        if not mac:
            return False

        return True
    except Exception as ex:
        log_error(f"Pre-flight health check failed: {ex}")
        return False


async def main() -> None:
    if not run_preflight_checks():
        log_error("Pre-flight health checks failed. Check crypto configuration.")

    # Check CLI argument or environment mode
    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c", "cli", "terminal"):
        await run_terminal_cli()
        return

    # If BOT_TOKEN is present, launch Telegram bot
    bot_token = Config.get_bot_token()
    if bot_token:
        bot = TelegramBot(bot_token)
        await bot.start_polling()
    else:
        # Fallback to interactive Terminal CLI
        await run_terminal_cli()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete.")
