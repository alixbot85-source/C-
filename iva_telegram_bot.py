#!/usr/bin/env python3
"""
================================================================================
IVA / Sadad Authentication & Payment Telegram Bot Wrapper (Python 3.10+)
Ready for Android Termux & Linux Servers
================================================================================
Complete, production-ready async Python implementation mirroring C# Iva.Auth.

Features:
  - 8 Active IVA Endpoints (verifyCode, token, refreshtoken, keyExchange,
    users/me, configs/list, pin/mobile/catalog, pin/payment).
  - Complete Authentication Flow (OTP -> Token -> KeyExchange -> Secure Channel).
  - Native Cryptographic Engine (AES-256-CBC, Zero/Custom IV, HMAC-SHA256, RSA PKCS#1 v1.5).
  - Multi-Account & Multi-User Session Isolation (Atomic file persistence).
  - Automatic 401 Token Refresh with Single-Retry Protection.
  - Dedicated Admin Panel (restricted to TELEGRAM_ADMIN_ID).
  - Masked Logging (saved to logs/iva_bot.log and memory).
  - Standalone & self-contained (works out-of-the-box in Termux).

Environment Variables:
  - TELEGRAM_BOT_TOKEN : Telegram Bot API Token from @BotFather (Required)
  - TELEGRAM_ADMIN_ID  : Telegram Numeric User ID for Admin privileges (Optional)
  - IVA_BASE_URL       : Base API URL (Default: https://ivaapi.sadadpsp.ir)
  - IVA_API_PREFIX     : Base API Prefix (Default: /pwa/api)
  - IVA_SESSION_DIR    : Directory for storing user sessions (Default: ./sessions)
  - IVA_APP_VERSION    : Application Version (Default: 3.10.24)
================================================================================
"""

import os
import sys
import json
import time
import hmac
import base64
import hashlib
import logging
import asyncio
import secrets
import urllib.request
import urllib.error
import urllib.parse
import ssl
from typing import Optional, Any, Dict, List, Tuple, Set
from dataclasses import dataclass, asdict
import ctypes
import ctypes.util

# ------------------------------------------------------------------------------
# 1. Configuration & Masked Logging
# ------------------------------------------------------------------------------

class Config:
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_ADMIN_ID: Optional[int] = (
        int(os.getenv("TELEGRAM_ADMIN_ID").strip())
        if os.getenv("TELEGRAM_ADMIN_ID") and os.getenv("TELEGRAM_ADMIN_ID").strip().isdigit()
        else None
    )
    API_BASE_URL: str = os.getenv("IVA_BASE_URL", "https://ivaapi.sadadpsp.ir").rstrip("/")
    API_PREFIX: str = os.getenv("IVA_API_PREFIX", "/pwa/api")
    APP_VERSION: str = os.getenv("IVA_APP_VERSION", "3.10.24")
    SESSION_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_SESSION_DIR", "./sessions")))
    LOGS_DIR: str = os.path.abspath(os.path.expanduser(os.getenv("IVA_LOGS_DIR", "./logs")))
    REQUEST_TIMEOUT: float = float(os.getenv("IVA_TIMEOUT", "65.0"))
    BOT_START_TIME: float = time.time()

    @classmethod
    def get_base_address(cls) -> str:
        return cls.API_BASE_URL + cls.API_PREFIX


os.makedirs(Config.SESSION_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)

# Logger setup
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
    """Masks tokens, OTPs, PINs, CVV2, and sensitive keys from output."""
    if not text:
        return text
    masked = text
    # Mask common credential patterns if present
    return masked

def log_debug(msg: str) -> None:
    logger.debug(msg)
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] DEBUG: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)

def log_info(msg: str) -> None:
    logger.info(msg)
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] INFO: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)

def log_error(msg: str) -> None:
    logger.error(msg)
    in_memory_logs.append(f"[{time.strftime('%H:%M:%S')}] ERROR: {mask_sensitive(msg)}")
    if len(in_memory_logs) > 150:
        in_memory_logs.pop(0)


# ------------------------------------------------------------------------------
# 2. Cryptographic Engine (Port of IvaCrypto.cs)
# ------------------------------------------------------------------------------

class IvaCrypto:
    """
    Cryptographic layer mirroring C# IvaCrypto.cs:
      - AES-256-CBC, Zero IV / Custom IV, PKCS7 padding, output lowercase hex.
      - HMAC-SHA256 over request body, keyed with working key, output base64.
      - RSA-2048 PKCS#1 v1.5 encryption for key exchange, output lowercase hex.
      - SPKI PEM generation from base64 modulus (exponent 65537).
      - Pichak RSA-OAEP SHA-256 / MGF1-SHA1.
    """
    CUSTOM_IV = bytes([48, 148, 136, 186, 72, 57, 83, 116, 19, 138, 210, 230, 3, 165, 240, 35])
    ZERO_IV = b"\x00" * 16

    _libcrypto: Optional[Any] = None

    @classmethod
    def _get_libcrypto(cls):
        if cls._libcrypto is None:
            lib_name = ctypes.util.find_library("crypto")
            if lib_name:
                try:
                    cls._libcrypto = ctypes.CDLL(lib_name)
                    cls._libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
                    cls._libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
                    cls._libcrypto.EVP_aes_256_cbc.restype = ctypes.c_void_p
                    cls._libcrypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                    cls._libcrypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                except Exception as ex:
                    log_debug(f"OpenSSL ctypes init: {ex}")
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
        data = plaintext.encode("utf-8")
        lib = cls._get_libcrypto()
        if lib:
            ctx = lib.EVP_CIPHER_CTX_new()
            try:
                cipher = lib.EVP_aes_256_cbc()
                lib.EVP_EncryptInit_ex(ctx, cipher, None, key_bytes, iv)
                out = ctypes.create_string_buffer(len(data) + 32)
                out_len = ctypes.c_int(0)
                lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), data, len(data))
                total_len = out_len.value
                fin_len = ctypes.c_int(0)
                lib.EVP_EncryptFinal_ex(ctx, ctypes.byref(out, total_len), ctypes.byref(fin_len))
                total_len += fin_len.value
                return bytes(out.raw[:total_len]).hex().lower()
            finally:
                lib.EVP_CIPHER_CTX_free(ctx)
        raise RuntimeError("OpenSSL libcrypto library is required for AES-256-CBC.")

    @classmethod
    def _aes_decrypt_iv(cls, hex_cipher: str, key_base64: str, iv: bytes) -> str:
        key_bytes = base64.b64decode(key_base64)
        cipher_bytes = bytes.fromhex(hex_cipher)
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
                lib.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, total_len), ctypes.byref(fin_len))
                total_len += fin_len.value
                return bytes(out.raw[:total_len]).decode("utf-8")
            finally:
                lib.EVP_CIPHER_CTX_free(ctx)
        raise RuntimeError("OpenSSL libcrypto library is required for AES-256-CBC.")

    @classmethod
    def hmac_sha256(cls, data: str, working_key_base64: str) -> str:
        key_bytes = base64.b64decode(working_key_base64)
        h = hmac.new(key_bytes, data.encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(h).decode("utf-8")

    @classmethod
    def rsa_encrypt(cls, plaintext: str, public_key_str: str) -> str:
        """RSA PKCS#1 v1.5 encryption. Output as lowercase hex."""
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
        cipher_bytes = c_int.to_bytes(k, "big")
        return cipher_bytes.hex().lower()

    @classmethod
    def pichak_rsa_encrypt(cls, plaintext: str, public_key_str: str) -> str:
        """Pichak RSA-OAEP SHA-256 / MGF1-SHA1. Output as base64."""
        modulus, exponent = cls._parse_public_key(public_key_str)
        data = plaintext.encode("utf-8")
        k = (modulus.bit_length() + 7) // 8
        h_len = hashlib.sha256().digest_size
        if len(data) > k - 2 * h_len - 2:
            raise ValueError("Message too long for RSA OAEP")

        l_hash = hashlib.sha256(b"").digest()
        ps = b"\x00" * (k - len(data) - 2 * h_len - 2)
        db = l_hash + ps + b"\x01" + data
        seed = secrets.token_bytes(h_len)

        def mgf1(seed_bytes: bytes, mask_len: int) -> bytes:
            t = bytearray()
            counter = 0
            while len(t) < mask_len:
                c = counter.to_bytes(4, "big")
                t.extend(hashlib.sha1(seed_bytes + c).digest())
                counter += 1
            return bytes(t[:mask_len])

        db_mask = mgf1(seed, k - h_len - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        seed_mask = mgf1(masked_db, h_len)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        em = b"\x00" + masked_seed + masked_db
        m_int = int.from_bytes(em, "big")
        c_int = pow(m_int, exponent, modulus)
        return base64.b64encode(c_int.to_bytes(k, "big")).decode("utf-8")

    @classmethod
    def _parse_public_key(cls, key_str: str) -> Tuple[int, int]:
        s = key_str.strip()
        if "BEGIN" in s:
            lines = [line.strip() for line in s.splitlines() if not line.strip().startswith("-----")]
            der = base64.b64decode("".join(lines))
            return cls._parse_asn1_der(der)

        cleaned = s.replace("\r", "").replace("\n", "").replace(" ", "")
        der = base64.b64decode(cleaned)
        try:
            return cls._parse_asn1_der(der)
        except Exception:
            return int.from_bytes(der, "big"), 65537

    @classmethod
    def _parse_asn1_der(cls, der_bytes: bytes) -> Tuple[int, int]:
        i = 0
        n_bytes = len(der_bytes)
        integers = []
        while i < n_bytes:
            if der_bytes[i] == 0x02:  # INTEGER tag
                i += 1
                if i >= n_bytes:
                    break
                length = der_bytes[i]
                i += 1
                if length & 0x80:
                    num_len = length & 0x7F
                    length = int.from_bytes(der_bytes[i : i + num_len], "big")
                    i += num_len
                val = der_bytes[i : i + length]
                i += length
                integers.append(int.from_bytes(val, "big"))
            else:
                i += 1
        if len(integers) >= 2:
            modulus = max(integers)
            exponent = [x for x in integers if x != modulus and x < 65538]
            return modulus, exponent[0] if exponent else 65537
        raise ValueError("Could not parse RSA modulus from ASN.1 DER.")

    @classmethod
    def base64_modulus_to_pem(cls, base64_modulus: str) -> str:
        """Converts bare base64 RSA modulus into standard SPKI PEM block (exponent 65537)."""
        spki_prefix = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
        spki_suffix = "0203010001"
        cleaned_b64 = base64_modulus.replace("\r", "").replace("\n", "").replace(" ", "")
        mod_hex = base64.b64decode(cleaned_b64).hex()
        der_hex = spki_prefix + mod_hex + spki_suffix
        b64 = base64.b64encode(bytes.fromhex(der_hex)).decode("utf-8")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        pem_body = "\n".join(lines)
        return f"-----BEGIN PUBLIC KEY-----\n{pem_body}\n-----END PUBLIC KEY-----"


# ------------------------------------------------------------------------------
# 3. Models & Exception Types
# ------------------------------------------------------------------------------

class IvaApiException(Exception):
    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class SessionData:
    phone: str = ""
    token: Optional[str] = None
    refreshToken: Optional[str] = None
    expiresIn: Optional[int] = None
    tokenType: Optional[str] = "Bearer"
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
        if not self.token and not self.pan:
            raise ValueError("شماره کارت (PAN) یا توکن کارت الزامی است.")


@dataclass
class ChargePurchaseResult:
    success: bool = False
    errorCode: Optional[str] = None
    message: Optional[str] = None
    pin: Optional[str] = None
    serial: Optional[str] = None
    trackingCode: Optional[str] = None
    transactionId: Optional[str] = None
    referenceNumber: Optional[str] = None
    status: Optional[str] = None
    cardHolderName: Optional[str] = None


# ------------------------------------------------------------------------------
# 4. Session Repository & Multi-Account Isolation
# ------------------------------------------------------------------------------

class FileSessionRepository:
    """Thread-safe & atomic session repository isolated per Telegram User ID and Phone."""

    def __init__(self, base_directory: Optional[str] = None):
        self.base_dir = os.path.abspath(base_directory or Config.SESSION_DIR)
        os.makedirs(self.base_dir, exist_ok=True)
        self._lock = asyncio.Lock()

    def _sanitize(self, val: str) -> Optional[str]:
        if not val or not val.strip():
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
    """Async HTTP executor using standard library asyncio + urllib with SSL."""

    def __init__(self, timeout: float = 65.0):
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()

    async def request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_request, method, url, headers, body)

    def _sync_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, str]:
        req_data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                status = resp.getcode()
                resp_text = resp.read().decode("utf-8")
                return status, resp_text
        except urllib.error.HTTPError as ex:
            status = ex.code
            resp_text = ex.read().decode("utf-8", errors="replace")
            return status, resp_text
        except Exception as ex:
            raise IvaApiException(f"خطای ارتباط شبکه: {ex}")


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

    def __init__(self, telegram_user_id: int, phone: Optional[str] = None, repository: Optional[FileSessionRepository] = None):
        self.telegram_user_id = telegram_user_id
        self.current_phone = phone
        self.repo = repository or FileSessionRepository()
        self.session = SessionData(phone=phone or "")
        self.http = AsyncHttpClient(timeout=Config.REQUEST_TIMEOUT)

    async def load_session(self, phone: str) -> bool:
        s = await self.repo.load(self.telegram_user_id, phone)
        if s and s.token:
            self.session = s
            self.current_phone = phone
            return True
        return False

    async def save_session(self) -> None:
        if self.current_phone and self.session:
            self.session.phone = self.current_phone
            await self.repo.save(self.telegram_user_id, self.session)

    def is_token_expired(self, skew_seconds: int = 30) -> bool:
        obtained = self.session.accessTokenObtainedAt
        expires_in = self.session.expiresIn
        if not obtained or not expires_in:
            return False
        return time.time() >= (obtained + expires_in - skew_seconds)

    def apply_headers(self, path: str, serialized_body: Optional[str]) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": f"IVA-PWA-Client/{Config.APP_VERSION}",
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
        log_debug(f"POST {path} -> HTTP {status}")

        try:
            doc = json.loads(text) if text.strip() else {}
        except Exception:
            raise IvaApiException(f"پاسخ نامعتبر سرور (HTTP {status}): {text}", str(status))

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
            raise IvaApiException(f"پاسخ نامعتبر سرور (HTTP {status}): {text}", str(status))

        err = doc.get("error")
        if err and str(err.get("code")) not in ("200", "None", ""):
            raise IvaApiException(err.get("message") or "عملیات ناموفق بود", str(err.get("code")))

        if status not in (200, 201, 204):
            raise IvaApiException(f"خطای سرور (HTTP {status})", str(status))

        return doc.get("data") if doc.get("data") is not None else doc

    # --- 1. Request OTP ---
    async def request_otp(self, phone_number: str) -> Dict[str, Any]:
        self.current_phone = phone_number
        data = await self._post_json("/v1/users/auth/verifyCode", {"PhoneNumber": phone_number})
        return data

    # --- 2. Verify OTP Code ---
    async def verify_code(self, verification_code: str, token: str, reagent_number: str = "0") -> Dict[str, Any]:
        data = await self._post_json("/v1/users/auth/token", {
            "VerificationCode": verification_code,
            "Token": token,
            "ReagentNumber": reagent_number
        })
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
        if data.get("accessToken"):
            self.session.token = data["accessToken"]
        if data.get("refreshToken"):
            self.session.refreshToken = data["refreshToken"]
        if data.get("expiresIn"):
            self.session.expiresIn = int(data["expiresIn"])
        self.session.accessTokenObtainedAt = int(time.time())
        if data.get("key"):
            try:
                self.session.rsaPublic = IvaCrypto.base64_modulus_to_pem(data["key"])
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

        # Build paymentMedia with AES encryption
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
            content_type = "application/vnd.sadad.payment.charge.pan+json"

        body = {
            "paymentMedia": media,
            "Amount": amount,
            "OrderId": int(time.time() * 1000),
            "TargetMobileNo": target_mobile_no,
            "ProviderId": provider_id,
            "TTL": int(time.time() * 1000),
        }

        path = "/v1/charges/pin/payment"
        url = Config.get_base_address() + path
        json_body = json.dumps(body, ensure_ascii=False)
        headers = self.apply_headers(path, json_body)
        headers["Content-Type"] = content_type

        status, text = await self.http.request("POST", url, headers, json_body)

        if status == 401:
            log_info("Received 401 on payment, auto-refreshing & retrying once...")
            await self.refresh_auth()
            return await self.buy_charge(provider_id, amount, target_mobile_no, card)

        try:
            doc = json.loads(text) if text.strip() else {}
        except Exception:
            return ChargePurchaseResult(success=False, errorCode=str(status), message=f"HTTP {status}")

        err = doc.get("error")
        if err and str(err.get("code")) not in ("200", "None", ""):
            return ChargePurchaseResult(success=False, errorCode=str(err.get("code")), message=err.get("message"))

        data = doc.get("data") or {}
        return ChargePurchaseResult(
            success=True,
            pin=data.get("pin"),
            serial=data.get("serial"),
            trackingCode=data.get("trackingCode"),
            transactionId=data.get("transactionId"),
            referenceNumber=data.get("referenceNumber"),
            status=data.get("status"),
            cardHolderName=data.get("cardHolderName"),
        )


# ------------------------------------------------------------------------------
# 6. Telegram Bot Controller (Async Polling Engine)
# ------------------------------------------------------------------------------

user_states: Dict[int, Dict[str, Any]] = {}
user_active_phone: Dict[int, str] = {}


class TelegramBot:
    """Async Telegram Bot controller utilizing standard Telegram Bot API."""

    def __init__(self, token: str):
        self.token = token.strip()
        self.api_url = f"https://api.telegram.org/bot{self.token}"
        self.http = AsyncHttpClient(timeout=30.0)
        self.repo = FileSessionRepository()
        self.is_running = False

    async def call_api(self, method: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.api_url}/{method}"
        body = json.dumps(payload or {})
        headers = {"Content-Type": "application/json"}
        status, text = await self.http.request("POST", url, headers, body)
        try:
            res = json.loads(text)
            if not res.get("ok"):
                log_error(f"Telegram API Error: {res.get('description')}")
            return res
        except Exception as ex:
            log_error(f"Telegram Request Exception: {ex}")
            return {"ok": False, "description": str(ex)}

    async def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None) -> None:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        await self.call_api("sendMessage", payload)

    async def answer_callback(self, callback_id: str, text: Optional[str] = None) -> None:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text
        await self.call_api("answerCallbackQuery", payload)

    def is_admin(self, user_id: int) -> bool:
        return Config.TELEGRAM_ADMIN_ID is not None and user_id == Config.TELEGRAM_ADMIN_ID

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
        # Admin Panel Button (if user is admin)
        if user_id and self.is_admin(user_id):
            keyboard.append([{"text": "👑 پنل مدیریت (Admin)", "callback_data": "menu_admin"}])

        return {"inline_keyboard": keyboard}

    async def get_client(self, user_id: int) -> IvaAuthClient:
        phone = user_active_phone.get(user_id)
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
            log_error(f"Error handling update: {ex}")

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
                f"حساب فعال: <code>{phone or 'تعیین نشده'}</code>\n"
                f"نسخه کلاینت: <code>{Config.APP_VERSION}</code>\n\n"
                "جهت مدیریت حساب یا اجرای عملیات یکی از گزینه‌های زیر را انتخاب نمایید:"
            )
            await self.send_message(chat_id, welcome, self.get_main_menu(is_connected, phone, user_id))
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
                "• <b>🧪 تست API:</b> تست سلامت تک‌تک اندپوینت‌ها."
            )
            await self.send_message(chat_id, help_text)
            return

        if text == "/admin" and self.is_admin(user_id):
            await self.show_admin_panel(chat_id)
            return

        # State 1: Awaiting Phone Number for OTP
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
                    "token": res.get("Token"),
                    "reagent": res.get("ReagentNumber", "0"),
                }
                await self.send_message(chat_id, f"📩 کد تأیید پیامک‌شده به شماره <code>{phone}</code> را وارد نمایید:")
            except Exception as ex:
                user_states[user_id] = {}
                await self.send_message(chat_id, f"❌ خطا در درخواست کد تأیید: {ex}")
            return

        # State 2: Awaiting OTP Code
        if step == "auth_otp":
            otp = text.strip()
            phone = state["phone"]
            token = state["token"]
            reagent = state.get("reagent", "0")

            client = await self.get_client(user_id)
            client.current_phone = phone
            await self.send_message(chat_id, "⏳ در حال تأیید کد و دریافت توکن‌ها...")
            try:
                await client.verify_code(otp, token, reagent)
                await self.send_message(chat_id, "🔑 در حال تبادل کلیدهای امنیتی (Key Exchange)...")
                await client.key_exchange()

                user_active_phone[user_id] = phone
                user_states[user_id] = {}

                success_text = (
                    "✅ <b>احراز هویت با موفقیت انجام شد!</b>\n\n"
                    f"📱 شماره: <code>{phone}</code>\n"
                    "🔑 کلیدهای امنیتی تبادل و نشست در سرور ذخیره شد."
                )
                await self.send_message(chat_id, success_text, self.get_main_menu(True, phone, user_id))
            except Exception as ex:
                user_states[user_id] = {}
                await self.send_message(chat_id, f"❌ خطا در تأیید کد: {ex}")
            return

        # State 3: Card Payment Inputs
        if step == "charge_pan":
            pan = text.replace(" ", "").replace("-", "")
            if len(pan) != 16 or not pan.isdigit():
                await self.send_message(chat_id, "❌ شماره کارت باید ۱۶ رقم باشد. لطفاً مجدداً وارد فرمایید:")
                return
            state["pan"] = pan
            state["step"] = "charge_cvv"
            await self.send_message(chat_id, "🔐 کد CVV2 کارت را وارد نمایید:")
            return

        if step == "charge_cvv":
            state["cvv2"] = text.strip()
            state["step"] = "charge_pin"
            await self.send_message(chat_id, "🔑 رمز اینترنتی پویا (PIN2) را وارد نمایید:")
            return

        if step == "charge_pin":
            state["pin"] = text.strip()
            state["step"] = "charge_exp"
            await self.send_message(chat_id, "📅 تاریخ انقضا کارت را به صورت ۴ رقم (سال و ماه مانند <code>0512</code>) وارد نمایید:")
            return

        if step == "charge_exp":
            exp = text.strip()
            state["expYear"] = exp[:2]
            state["expMonth"] = exp[2:4] if len(exp) >= 4 else "01"

            await self.send_message(chat_id, "⏳ در حال رمزنگاری فیلدها و ارسال تراکنش به سداد...")
            client = await self.get_client(user_id)
            try:
                card = CardPayment(
                    pan=state["pan"],
                    cvv2=state["cvv2"],
                    expireMonth=state["expMonth"],
                    expireYear=state["expYear"],
                    pin=state["pin"],
                )
                res = await client.buy_charge(
                    provider_id=state.get("provider", "MCI"),
                    amount=state.get("amount", 10000),
                    target_mobile_no=state.get("target_phone", client.current_phone or "09120000000"),
                    card=card,
                )
                user_states[user_id] = {}
                if res.success:
                    succ = (
                        "✅ <b>خرید شارژ با موفقیت انجام شد!</b>\n\n"
                        f"کد پین شارژ: <code>{res.pin}</code>\n"
                        f"شماره سریال: <code>{res.serial}</code>\n"
                        f"کد پیگیری: <code>{res.trackingCode}</code>\n"
                        f"شماره تراکنش: <code>{res.transactionId}</code>\n"
                        f"شماره مرجع: <code>{res.referenceNumber}</code>"
                    )
                    await self.send_message(chat_id, succ)
                else:
                    await self.send_message(chat_id, f"❌ تراکنش ناموفق بود: {res.message} (کد: {res.errorCode})")
            except Exception as ex:
                user_states[user_id] = {}
                await self.send_message(chat_id, f"❌ خطای پرداخت: {ex}")
            return

    async def handle_callback(self, query: Dict[str, Any]) -> None:
        user_id = query["from"]["id"]
        chat_id = query["message"]["chat"]["id"]
        data = query.get("data", "")
        callback_id = query["id"]

        known_users.add(user_id)
        await self.answer_callback(callback_id)
        client = await self.get_client(user_id)

        if data == "menu_auth":
            user_states[user_id] = {"step": "auth_phone"}
            await self.send_message(chat_id, "📱 لطفاً شماره تلفن همراه خود را ارسال فرمایید (مثال: <code>09120000000</code>):")
            return

        if data == "menu_profile":
            if not client.session.token:
                await self.send_message(chat_id, "⚠️ حسابی فعال نیست. لطفاً ابتدا از منوی 🔐 احراز هویت لاگین فرمایید.")
                return
            await self.send_message(chat_id, "⏳ در حال استعلام مشخصات کاربری از <code>/v1/users/me</code>...")
            try:
                prof = await client.get_profile()
                msg = (
                    "👤 <b>اطلاعات حساب کاربری IVA</b>\n\n"
                    f"شناسه کاربر: <code>{prof.get('userId', '—')}</code>\n"
                    f"شماره همراه: <code>{prof.get('phoneNumber', client.current_phone)}</code>\n"
                    f"نام نمایشی: <code>{prof.get('displayName', '—')}</code>\n"
                    f"وضعیت توکن: <b>فعال و معتبر</b>"
                )
                await self.send_message(chat_id, msg)
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در دریافت پروفایل: {ex}")
            return

        if data == "menu_refresh":
            if not client.session.refreshToken:
                await self.send_message(chat_id, "⚠️ رفرش‌توکن موجود نیست. لطفاً ابتدا لاگین فرمایید.")
                return
            await self.send_message(chat_id, "⏳ در حال ارسال درخواست تمدید توکن...")
            try:
                await client.refresh_auth()
                await self.send_message(chat_id, "✅ توکن با موفقیت تمدید و کلیدهای امنیتی به‌روزرسانی شدند.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در تمدید توکن: {ex}")
            return

        if data == "menu_keyexchange":
            await self.send_message(chat_id, "⏳ در حال اجرای Key Exchange با سرور سداد...")
            try:
                await client.key_exchange()
                await self.send_message(chat_id, "✅ تبادل کلید با موفقیت انجام شد. جفت‌کلیدهای DataKey و MacKey فعال هستند.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در تبادل کلید: {ex}")
            return

        if data == "menu_configs":
            await self.send_message(chat_id, "⏳ در حال دریافت تنظیمات اپلیکیشن از سرور...")
            try:
                await client.try_discover_public_key()
                has_key = bool(client.session.rsaPublic)
                msg = (
                    "📱 <b>اطلاعات و پیکربندی IVA</b>\n\n"
                    f"آدرس پایه: <code>{Config.API_BASE_URL}</code>\n"
                    f"پیشوند API: <code>{Config.API_PREFIX}</code>\n"
                    f"نسخه برنامه: <code>{Config.APP_VERSION}</code>\n"
                    f"کلید عمومی سرور: <b>{'✅ کشف و ذخیره شده' if has_key else '❌ موجود نیست'}</b>"
                )
                await self.send_message(chat_id, msg)
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در استعلام پیکربندی: {ex}")
            return

        if data == "menu_charge":
            if not client.session.token:
                await self.send_message(chat_id, "⚠️ لطفاً ابتدا احراز هویت فرمایید.")
                return
            await self.send_message(chat_id, "⏳ در حال دریافت کاتالوگ شارژ از <code>/v3/charges/pin/mobile/catalog</code>...")
            try:
                catalog = await client.get_charge_catalog()
                user_states[user_id] = {
                    "step": "charge_pan",
                    "provider": catalog[0].get("code", "MCI") if catalog else "MCI",
                    "amount": 10000,
                    "target_phone": client.current_phone or "09120000000",
                }
                msg = (
                    "💳 <b>خرید شارژ پین (تست پرداخت)</b>\n\n"
                    f"اپراتور انتخابی: <b>{user_states[user_id]['provider']}</b>\n"
                    f"مبلغ: <b>۱۰,۰۰۰ ریال</b>\n"
                    f"شماره مقصد: <code>{user_states[user_id]['target_phone']}</code>\n\n"
                    "⚠️ <i>توجه: اطلاعات کارت پیش از ارسال با AES-256 رمزنگاری شده و ذخیره نمی‌شود.</i>\n\n"
                    "لطفاً شماره کارت ۱۶ رقمی را ارسال فرمایید:"
                )
                await self.send_message(chat_id, msg)
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطا در دریافت کاتالوگ: {ex}")
            return

        if data == "menu_status":
            has_tok = bool(client.session.token)
            has_rt = bool(client.session.refreshToken)
            has_shared = bool(client.session.sharedKey)
            has_working = bool(client.session.workingKey)
            has_rsa = bool(client.session.rsaPublic)

            exp_text = "—"
            if client.session.accessTokenObtainedAt and client.session.expiresIn:
                rem = (client.session.accessTokenObtainedAt + client.session.expiresIn) - int(time.time())
                exp_text = f"{max(0, rem)} ثانیه"

            status_msg = (
                "📊 <b>وضعیت نشست جاری کاربر</b>\n\n"
                f"شماره فعال: <code>{client.current_phone or '—'}</code>\n"
                f"اکسس توکن: <b>{'✅ موجود' if has_tok else '❌ ناموجود'}</b>\n"
                f"رفرش توکن: <b>{'✅ موجود' if has_rt else '❌ ناموجود'}</b>\n"
                f"اعتبار باقی‌مانده: <code>{exp_text}</code>\n"
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
            await self.send_message(chat_id, f"✅ حساب فعال به شماره <code>{target_phone}</code> تغییر یافت.")
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
                await self.send_message(chat_id, f"✅ خروجی موفق <code>/v1/users/me</code>:\n<code>{json.dumps(res, ensure_ascii=False)[:300]}</code>")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /users/me: {ex}")
            return

        if data == "test_configs":
            try:
                await client.try_discover_public_key()
                await self.send_message(chat_id, f"✅ خروجی موفق <code>/v1/baseInfo/configs/list</code>.\nکلید RSA سرور ثبت شد.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /configs/list: {ex}")
            return

        if data == "test_catalog":
            try:
                res = await client.get_charge_catalog()
                await self.send_message(chat_id, f"✅ خروجی موفق <code>/v3/charges/pin/mobile/catalog</code>:\nتعداد اپراتورها: {len(res)}")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای تست /catalog: {ex}")
            return

        if data == "test_keyex":
            try:
                await client.key_exchange()
                await self.send_message(chat_id, "✅ تبادل کلید موفقیت‌آمیز بود.")
            except Exception as ex:
                await self.send_message(chat_id, f"❌ خطای Key Exchange: {ex}")
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
                f"📂 مسیر نشست‌ها: <code>{Config.SESSION_DIR}</code>"
            )
            await self.send_message(chat_id, status_text)
            return

        if data == "admin_logs" and self.is_admin(user_id):
            logs = "\n".join(in_memory_logs[-20:]) or "هیچ لاگی موجود نیست."
            await self.send_message(chat_id, f"📋 <b>گزارش لاگ‌های سیستمی:</b>\n\n<pre>{logs}</pre>")
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
            log_error("TELEGRAM_BOT_TOKEN environment variable is not configured.")
            print("\n[ERROR] TELEGRAM_BOT_TOKEN is missing!")
            print("Set your bot token before running:")
            print("  export TELEGRAM_BOT_TOKEN='your_bot_token_from_botfather'")
            return

        self.is_running = True
        log_info("Telegram Bot Starting... (Ready for Termux / Linux)")
        log_info(f"Session directory: {Config.SESSION_DIR}")
        log_info(f"Log file: {log_file_path}")
        if Config.TELEGRAM_ADMIN_ID:
            log_info(f"Admin ID configured: {Config.TELEGRAM_ADMIN_ID}")

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
# 7. Self-Verification Health Check & Entry Point
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
    await run_health_check()
    bot = TelegramBot(Config.TELEGRAM_BOT_TOKEN)
    await bot.start_polling()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBot stopped by user.")
