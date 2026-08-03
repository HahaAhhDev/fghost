#!/usr/bin/env python3
"""
OblivX - Military-Grade AES-256-GCM Encryption/Decryption Tool with Argon2id
Enhanced, hardened, and production-ready version.
v26.3.8 - By monkeyheheh
"""

import argparse
import base64
import os
import getpass
import logging
import shutil
import string
import secrets
import sys
import subprocess
from pathlib import Path
import json
import time
from typing import Optional, Any, Dict, List, Union

# ---------------------------------------------------------------------------
# Dependency check (fail fast and clean)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import box

    from argon2 import low_level
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    import requests

    status = "INSTALLED"
    ce = Console()
    inp = Prompt()

except ImportError as e:
    print("Missing dependencies. Install them with (Idk if thats all of them):")
    print("    pip install scapy cryptography argon2-cffi rich requests")
    print(f"Details: {e}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------
SALT_SIZE: int = 16
NONCE_SIZE: int = 12
DEFAULT_TIME_COST: int = 3
DEFAULT_MEMORY_COST: int = 65536          # 64 MiB - good balance
DEFAULT_PARALLELISM: int = 4
MAX_FILE_SIZE: int = 100 * 1024 * 1024   # 100 MB
MIN_PASSWORD_LENGTH: int = 8

# ---------------------------------------------------------------------------
# Custom exceptions (never leak sensitive details)
# ---------------------------------------------------------------------------
class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


class StorageError(Exception):
    """Raised on storage backend failures."""
    pass


# ---------------------------------------------------------------------------
# GlobalStorage - robust paste.rs backed key-value store
# ---------------------------------------------------------------------------
class GlobalStorage:
    """Persistent key-value store using paste.rs + local URL cache."""

    def __init__(self, namespace: str):
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("Namespace must be a non-empty string")
        self.namespace = namespace.strip()
        self.data: Dict[str, Any] = {}
        self.paste_url: Optional[str] = None
        self._timeout = 20
        self._cache_file = Path.home() / f".oblivx_{self.namespace}.url"
        self._load_url()

    def _load_url(self) -> None:
        """Load previously saved paste URL from local cache."""
        try:
            if self._cache_file.exists():
                url = self._cache_file.read_text(encoding="utf-8").strip()
                if url.startswith("https://paste.rs/"):
                    self.paste_url = url
        except Exception:
            self.paste_url = None

    def _save_url(self) -> None:
        """Persist paste URL locally so data survives restarts."""
        try:
            if self.paste_url:
                self._cache_file.write_text(self.paste_url, encoding="utf-8")
                try:
                    self._cache_file.chmod(0o600)
                except Exception:
                    pass
        except Exception as e:
            logging.warning(f"Could not cache paste URL: {e}")

    def _save_to_paste(self) -> None:
        """Upload current data to paste.rs."""
        try:
            payload = json.dumps(self.data, separators=(",", ":"), ensure_ascii=False)
            resp = requests.post(
                "https://paste.rs",
                data=payload.encode("utf-8"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            self.paste_url = resp.text.strip()
            self._save_url()
            logging.debug(f"Saved to {self.paste_url}")
        except requests.RequestException as e:
            raise StorageError(f"Failed to save data: {e}") from e

    def _load_from_paste(self) -> None:
        """Download and parse data from paste.rs."""
        if not self.paste_url:
            self.data = {}
            return
        try:
            if not self.paste_url.startswith("https://paste.rs/"):
                raise ValueError("Invalid paste.rs URL")
            resp = requests.get(self.paste_url, timeout=self._timeout)
            resp.raise_for_status()
            loaded = json.loads(resp.text)
            if not isinstance(loaded, dict):
                raise ValueError("Remote data is not a dict")
            self.data = loaded
        except Exception as e:
            logging.warning(f"Could not load remote data: {e}")
            self.data = {}

    def set(self, key: str, value: Any) -> None:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be non-empty string")
        if value is None:
            raise ValueError("Value cannot be None")
        self._load_from_paste()
        self.data[key] = value
        self._save_to_paste()

    def get(self, key: str, default: Any = None) -> Any:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be non-empty string")
        self._load_from_paste()
        return self.data.get(key, default)

    def delete(self, key: str) -> bool:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be non-empty string")
        self._load_from_paste()
        if key in self.data:
            del self.data[key]
            self._save_to_paste()
            return True
        return False

    def clear(self) -> None:
        self.data = {}
        self._save_to_paste()

    def keys(self) -> List[str]:
        self._load_from_paste()
        return list(self.data.keys())

    def size(self) -> int:
        self._load_from_paste()
        return len(self.data)


# ---------------------------------------------------------------------------
# File helpers (original names preserved)
# ---------------------------------------------------------------------------
def rm_tree(path: Union[str, Path]) -> None:
    p = Path(path)
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def runos(cmd: str) -> None:
    """Run a command via the shell (use with caution)."""
    os.system(cmd)


def run(cmd: str) -> str:
    """Run a shell command and return stdout."""
    result = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    return result.stdout


def show(text: str) -> None:
    print(text)


def checkpath(path: Union[str, Path]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.touch()


def readfile(path: Union[str, Path]) -> str:
    checkpath(path)
    return Path(path).read_text(encoding="utf-8").strip()


def writefile(path: Union[str, Path], content: str) -> None:
    checkpath(path)
    Path(path).write_text(content, encoding="utf-8")


def writeapp(path: Union[str, Path], content: str) -> None:
    checkpath(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + content)


def writeinline(path: Union[str, Path], line: int, content: str) -> None:
    checkpath(path)
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines()
    while len(lines) <= line:
        lines.append("")
    lines[line] = content
    p.write_text("\n".join(lines), encoding="utf-8")


def genpass(length: int = 16) -> str:
    """Generate a cryptographically secure password."""
    if length < 8:
        length = 8
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def extract(path: Union[str, Path], line: int = -1) -> str:
    checkpath(path)
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    if not lines:
        return ""
    try:
        return lines[line]
    except IndexError:
        return ""


# ---------------------------------------------------------------------------
# Encoding helpers (original names preserved)
# ---------------------------------------------------------------------------
def encode_binary(text: str) -> str:
    return " ".join(format(ord(c), "08b") for c in text)


def decode_binary(binary: str) -> str:
    try:
        return "".join(chr(int(b, 2)) for b in binary.split())
    except ValueError as e:
        raise ValueError(f"Invalid binary data: {e}") from e


def encode_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def decode_hex(hex_text: str) -> str:
    try:
        return bytes.fromhex(hex_text).decode("utf-8")
    except ValueError as e:
        raise ValueError(f"Invalid hex data: {e}") from e


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(encoded_text: str) -> str:
    try:
        return base64.b64decode(encoded_text.encode("ascii")).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Invalid Base64 data: {e}") from e


# ---------------------------------------------------------------------------
# Core crypto
# ---------------------------------------------------------------------------
def _derive_key(
    password: str,
    salt: bytes,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    if time_cost < 1:
        raise ValueError("time_cost must be >= 1")
    if memory_cost < 8192:
        raise ValueError("memory_cost must be >= 8192 KiB")
    if parallelism < 1:
        raise ValueError("parallelism must be >= 1")

    try:
        return low_level.hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            hash_len=32,
            type=low_level.Type.ID,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )
    except Exception as e:
        raise EncryptionError("Key derivation failed") from e


def encrypt(text: str, password: str) -> str:
    """Encrypt a string → base64 ciphertext."""
    if not password:
        raise ValueError("Password cannot be empty")
    return encrypt_data(text.encode("utf-8"), password)


def decrypt(encrypted: str, password: str) -> str:
    """Decrypt base64 ciphertext → string."""
    if not password:
        raise ValueError("Password cannot be empty")
    return decrypt_data(encrypted, password).decode("utf-8")


def encrypt_data(
    plaintext: bytes,
    password: str,
    aad: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> str:
    if not isinstance(plaintext, bytes):
        raise ValueError("plaintext must be bytes")
    if not password:
        raise ValueError("Password cannot be empty")
    if len(plaintext) > MAX_FILE_SIZE:
        raise ValueError("Plaintext too large")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt, time_cost, memory_cost, parallelism)

    try:
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, aad)
        raw = salt + nonce + ciphertext
        return base64.b64encode(raw).decode("ascii")
    except Exception as e:
        raise EncryptionError("Encryption failed") from e
    finally:
        # Best-effort cleanup
        del key


def decrypt_data(
    encrypted_data: str,
    password: str,
    aad: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    if not encrypted_data or not password:
        raise ValueError("encrypted_data and password are required")

    try:
        raw = base64.b64decode(encrypted_data)
    except Exception as e:
        raise DecryptionError("Invalid base64 data") from e

    min_len = SALT_SIZE + NONCE_SIZE + 16
    if len(raw) < min_len:
        raise DecryptionError("Ciphertext too short")

    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE :]

    key = _derive_key(password, salt, time_cost, memory_cost, parallelism)

    try:
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("Invalid password or corrupted data")
    except Exception as e:
        raise DecryptionError("Decryption failed") from e
    finally:
        del key


def encrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
    aad: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> None:
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    size = input_path.stat().st_size
    if size == 0:
        raise ValueError("Cannot encrypt empty file")
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({size} bytes)")

    plaintext = input_path.read_bytes()
    try:
        token = encrypt_data(plaintext, password, aad, time_cost, memory_cost, parallelism)
        tmp = output_path.with_suffix(output_path.suffix + ".tmp")
        tmp.write_text(token, encoding="ascii")
        tmp.replace(output_path)
        logging.info(f"Encrypted {input_path} → {output_path}")
    finally:
        del plaintext


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: str,
    aad: Optional[bytes] = None,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> None:
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    token = input_path.read_text(encoding="ascii")
    try:
        plaintext = decrypt_data(token, password, aad, time_cost, memory_cost, parallelism)
        tmp = output_path.with_suffix(output_path.suffix + ".tmp")
        tmp.write_bytes(plaintext)
        tmp.replace(output_path)
        logging.info(f"Decrypted {input_path} → {output_path}")
    finally:
        del token


# ---------------------------------------------------------------------------
# Logging & CLI
# ---------------------------------------------------------------------------
def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)8s] %(name)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="OblivX – AES-256-GCM + Argon2id encryption tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s encrypt-message "hello world"
  %(prog)s decrypt-message "base64..."
  %(prog)s encrypt-file secret.pdf secret.pdf.enc
  %(prog)s decrypt-file secret.pdf.enc secret.pdf
""",
    )

    parser.add_argument("--time-cost", type=int, default=DEFAULT_TIME_COST,
                        help=f"Argon2 time cost (default: {DEFAULT_TIME_COST})")
    parser.add_argument("--memory-cost", type=int, default=DEFAULT_MEMORY_COST,
                        help=f"Argon2 memory cost KiB (default: {DEFAULT_MEMORY_COST})")
    parser.add_argument("--parallelism", type=int, default=DEFAULT_PARALLELISM,
                        help=f"Argon2 parallelism (default: {DEFAULT_PARALLELISM})")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--version", action="version", version="OblivX 2.1")

    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt-message
    p = sub.add_parser("encrypt-message", help="Encrypt a text message")
    p.add_argument("message")
    p.add_argument("--aad", help="Additional authenticated data (base64)")

    # decrypt-message
    p = sub.add_parser("decrypt-message", help="Decrypt a text message")
    p.add_argument("encrypted")
    p.add_argument("--aad", help="Additional authenticated data (base64)")

    # encrypt-file
    p = sub.add_parser("encrypt-file", help="Encrypt a file")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--aad", help="Additional authenticated data (base64)")

    # decrypt-file
    p = sub.add_parser("decrypt-file", help="Decrypt a file")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--aad", help="Additional authenticated data (base64)")

    args = parser.parse_args()
    setup_logging(args.log_level)

    # Basic parameter sanity
    if not (1 <= args.time_cost <= 10):
        parser.error("time-cost must be 1-10")
    if not (8192 <= args.memory_cost <= 1048576):
        parser.error("memory-cost must be 8192-1048576")
    if not (1 <= args.parallelism <= 16):
        parser.error("parallelism must be 1-16")

    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        logging.error(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        sys.exit(1)

    aad_bytes = None
    if getattr(args, "aad", None):
        try:
            aad_bytes = base64.b64decode(args.aad)
        except Exception:
            logging.error("Invalid --aad (must be base64)")
            sys.exit(1)

    try:
        if args.command == "encrypt-message":
            result = encrypt_data(
                args.message.encode("utf-8"),
                password,
                aad_bytes,
                args.time_cost,
                args.memory_cost,
                args.parallelism,
            )
            print(result)

        elif args.command == "decrypt-message":
            result = decrypt_data(
                args.encrypted,
                password,
                aad_bytes,
                args.time_cost,
                args.memory_cost,
                args.parallelism,
            )
            print(result.decode("utf-8"))

        elif args.command == "encrypt-file":
            encrypt_file(
                args.input,
                args.output,
                password,
                aad_bytes,
                args.time_cost,
                args.memory_cost,
                args.parallelism,
            )
            print(f"✓ Encrypted → {args.output}")

        elif args.command == "decrypt-file":
            decrypt_file(
                args.input,
                args.output,
                password,
                aad_bytes,
                args.time_cost,
                args.memory_cost,
                args.parallelism,
            )
            print(f"✓ Decrypted → {args.output}")

    except (EncryptionError, DecryptionError, StorageError) as e:
        logging.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {type(e).__name__}: {e}")
        sys.exit(1)
    finally:
        # Best-effort password wipe
        password = "0" * len(password)
        del password


if __name__ == "__main__":
    cli()
