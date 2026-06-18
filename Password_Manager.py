import os
import json
import base64
import secrets
import hashlib
import getpass
import uuid
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
except ImportError:
    raise SystemExit(
        "\n  Missing dependency. Install with:\n"
        "  pip install cryptography\n"
    )


VAULT_DIR = Path.home() / ".vault_pm"
VAULT_FILE = VAULT_DIR / "vault.enc"
META_FILE = VAULT_DIR / "meta.json"

KDF_ITERATIONS = 600_000
SALT_BYTES = 32
NONCE_BYTES = 12
KEY_BYTES = 32


@dataclass
class Credential:
    id: str
    site: str
    username: str
    password: str
    url: str
    notes: str
    created_at: str
    updated_at: str
    tags: list[str] = field(default_factory=list)


class CryptoEngine:
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(master_password.encode("utf-8"))

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(NONCE_BYTES)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(payload: bytes, key: bytes) -> bytes:
        nonce = payload[:NONCE_BYTES]
        ciphertext = payload[NONCE_BYTES:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class Vault:
    def __init__(self):
        VAULT_DIR.mkdir(mode=0o700, exist_ok=True)
        self._key: Optional[bytes] = None
        self._credentials: list[Credential] = []
        self._meta: dict = {}

    def _load_meta(self) -> dict:
        if META_FILE.exists():
            with open(META_FILE) as f:
                return json.load(f)
        return {}

    def _save_meta(self, meta: dict):
        with open(META_FILE, "w") as f:
            json.dump(meta, f)
        os.chmod(META_FILE, 0o600)

    def is_initialized(self) -> bool:
        return VAULT_FILE.exists() and META_FILE.exists()

    def initialize(self, master_password: str):
        salt = secrets.token_bytes(SALT_BYTES)
        key = CryptoEngine.derive_key(master_password, salt)
        pw_hash = hashlib.sha256(master_password.encode()).hexdigest()

        meta = {
            "salt": base64.b64encode(salt).decode(),
            "pw_hash": pw_hash,
            "created_at": datetime.now().isoformat(),
        }
        self._save_meta(meta)
        self._key = key
        self._credentials = []
        self._persist()

    def unlock(self, master_password: str) -> bool:
        meta = self._load_meta()
        stored_hash = meta.get("pw_hash")
        if hashlib.sha256(master_password.encode()).hexdigest() != stored_hash:
            return False

        salt = base64.b64decode(meta["salt"])
        self._key = CryptoEngine.derive_key(master_password, salt)
        self._meta = meta
        self._load_vault()
        return True

    def _load_vault(self):
        if not VAULT_FILE.exists():
            self._credentials = []
            return
        with open(VAULT_FILE, "rb") as f:
            payload = f.read()
        try:
            raw = CryptoEngine.decrypt(payload, self._key)
            data = json.loads(raw.decode("utf-8"))
            self._credentials = [Credential(**c) for c in data]
        except (InvalidTag, json.JSONDecodeError):
            raise ValueError("Vault decryption failed. Wrong master password or corrupted vault.")

    def _persist(self):
        if self._key is None:
            raise RuntimeError("Vault is locked.")
        raw = json.dumps([asdict(c) for c in self._credentials]).encode("utf-8")
        payload = CryptoEngine.encrypt(raw, self._key)
        with open(VAULT_FILE, "wb") as f:
            f.write(payload)
        os.chmod(VAULT_FILE, 0o600)

    def add(self, credential: Credential):
        self._credentials.append(credential)
        self._persist()

    def update(self, credential: Credential):
        for i, c in enumerate(self._credentials):
            if c.id == credential.id:
                self._credentials[i] = credential
                self._persist()
                return True
        return False

    def delete(self, cred_id: str) -> bool:
        before = len(self._credentials)
        self._credentials = [c for c in self._credentials if c.id != cred_id]
        if len(self._credentials) < before:
            self._persist()
            return True
        return False

    def search(self, query: str) -> list[Credential]:
        q = query.lower()
        return [
            c for c in self._credentials
            if q in c.site.lower() or q in c.username.lower() or q in " ".join(c.tags).lower()
        ]

    def all(self) -> list[Credential]:
        return sorted(self._credentials, key=lambda c: c.site.lower())

    def get_by_id(self, cred_id: str) -> Optional[Credential]:
        return next((c for c in self._credentials if c.id == cred_id), None)


def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_sym = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd) if use_symbols else True
        if all([has_lower, has_upper, has_digit, has_sym]):
            return pwd


def password_strength(password: str) -> tuple[str, str]:
    score = 0
    if len(password) >= 12: score += 1
    if len(password) >= 20: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password): score += 1

    if score <= 2:
        return "Weak", "\033[91m"
    elif score <= 4:
        return "Fair", "\033[93m"
    elif score <= 5:
        return "Strong", "\033[96m"
    return "Very Strong", "\033[92m"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print("\033[93m")
    print("  ╔═══════════════════════════════════════╗")
    print("  ║       VAULT — PASSWORD MANAGER        ║")
    print("  ║      AES-256-GCM · PBKDF2 · SHA-256   ║")
    print("  ╚═══════════════════════════════════════╝")
    print("\033[0m")


def setup_vault(vault: Vault):
    print("\n  \033[93mFirst launch — Set up your master password.\033[0m")
    print("  This password encrypts your entire vault. \033[91mDo not lose it.\033[0m\n")
    while True:
        pw = getpass.getpass("  Create master password: ")
        confirm = getpass.getpass("  Confirm master password: ")
        if pw != confirm:
            print("  Passwords do not match. Try again.")
            continue
        if len(pw) < 8:
            print("  Password too short. Minimum 8 characters.")
            continue
        strength, color = password_strength(pw)
        print(f"  Password strength: {color}{strength}\033[0m")
        vault.initialize(pw)
        print("\n  \033[92m✓ Vault created and encrypted.\033[0m")
        return


def login(vault: Vault) -> bool:
    for attempt in range(3):
        pw = getpass.getpass("  Master password: ")
        if vault.unlock(pw):
            print("  \033[92m✓ Vault unlocked.\033[0m")
            return True
        remaining = 2 - attempt
        print(f"  \033[91m✗ Wrong password.{f' {remaining} attempt(s) remaining.' if remaining else ''}\033[0m")
    print("\n  Too many failed attempts. Exiting.")
    return False


def display_credentials(creds: list[Credential], reveal: bool = False):
    if not creds:
        print("\n  No credentials found.")
        return
    print(f"\n  {'ID':<10} {'Site':<22} {'Username':<24} {'Password'}")
    print("  " + "─" * 76)
    for c in creds:
        pw_display = c.password if reveal else "•" * min(len(c.password), 12)
        print(f"  {c.id:<10} {c.site[:20]:<22} {c.username[:22]:<24} {pw_display}")


def add_credential(vault: Vault):
    print("\n  — Add Credential —")
    site = input("  Site / App name: ").strip()
    if not site:
        print("  Site name is required.")
        return

    username = input("  Username / Email: ").strip()
    print("  Password: [1] Enter manually  [2] Generate")
    pw_choice = input("  Select: ").strip()

    if pw_choice == "2":
        try:
            length = int(input("  Length (default 20): ").strip() or "20")
        except ValueError:
            length = 20
        sym = input("  Include symbols? [Y/n]: ").strip().lower() != "n"
        password = generate_password(length, sym)
        print(f"  Generated: \033[96m{password}\033[0m")
    else:
        password = getpass.getpass("  Password: ")

    strength, color = password_strength(password)
    print(f"  Strength: {color}{strength}\033[0m")

    url = input("  URL (optional): ").strip()
    notes = input("  Notes (optional): ").strip()
    tags_raw = input("  Tags (comma-separated, optional): ").strip()
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    now = datetime.now().isoformat()
    cred = Credential(
        id=str(uuid.uuid4())[:8],
        site=site,
        username=username,
        password=password,
        url=url,
        notes=notes,
        created_at=now,
        updated_at=now,
        tags=tags,
    )
    vault.add(cred)
    print(f"\n  \033[92m✓ Saved — ID: {cred.id}\033[0m")


def view_all(vault: Vault):
    creds = vault.all()
    reveal = input("\n  Reveal passwords? [y/N]: ").strip().lower() == "y"
    display_credentials(creds, reveal)


def search_credentials(vault: Vault):
    query = input("\n  Search: ").strip()
    results = vault.search(query)
    reveal = input("  Reveal passwords? [y/N]: ").strip().lower() == "y"
    display_credentials(results, reveal)


def view_detail(vault: Vault):
    cred_id = input("\n  Credential ID: ").strip()
    cred = vault.get_by_id(cred_id)
    if not cred:
        print("  \033[91m✗ Not found.\033[0m")
        return
    strength, color = password_strength(cred.password)
    print(f"\n  {'Site':<16} {cred.site}")
    print(f"  {'Username':<16} {cred.username}")
    print(f"  {'Password':<16} {cred.password}")
    print(f"  {'Strength':<16} {color}{strength}\033[0m")
    print(f"  {'URL':<16} {cred.url or '—'}")
    print(f"  {'Notes':<16} {cred.notes or '—'}")
    print(f"  {'Tags':<16} {', '.join(cred.tags) or '—'}")
    print(f"  {'Created':<16} {cred.created_at[:19]}")
    print(f"  {'Updated':<16} {cred.updated_at[:19]}")


def delete_credential(vault: Vault):
    cred_id = input("\n  Credential ID to delete: ").strip()
    cred = vault.get_by_id(cred_id)
    if not cred:
        print("  \033[91m✗ Not found.\033[0m")
        return
    confirm = input(f"  Delete '{cred.site}' ({cred.username})? [yes/N]: ").strip()
    if confirm.lower() == "yes":
        vault.delete(cred_id)
        print("  \033[92m✓ Deleted.\033[0m")
    else:
        print("  Cancelled.")


def generate_standalone():
    print("\n  — Password Generator —")
    try:
        length = int(input("  Length (default 20): ").strip() or "20")
    except ValueError:
        length = 20
    sym = input("  Include symbols? [Y/n]: ").strip().lower() != "n"
    count = int(input("  How many to generate? (default 5): ").strip() or "5")
    print()
    for _ in range(count):
        pw = generate_password(length, sym)
        strength, color = password_strength(pw)
        print(f"  {color}{pw}\033[0m  [{strength}]")


def main():
    vault = Vault()

    clear()
    banner()

    if not vault.is_initialized():
        setup_vault(vault)
        input("\n  Press Enter to continue...")
    else:
        if not login(vault):
            return

    options = {
        "1": ("Add Credential", lambda: add_credential(vault)),
        "2": ("View All", lambda: view_all(vault)),
        "3": ("Search", lambda: search_credentials(vault)),
        "4": ("View Detail", lambda: view_detail(vault)),
        "5": ("Delete Credential", lambda: delete_credential(vault)),
        "6": ("Generate Password", generate_standalone),
        "0": ("Lock & Exit", None),
    }

    while True:
        clear()
        banner()
        count = len(vault.all())
        print(f"  \033[90m{count} credential(s) stored · AES-256-GCM encrypted\033[0m\n")
        print("  MAIN MENU\n")
        for key, (label, _) in options.items():
            print(f"    [{key}] {label}")
        print()

        choice = input("  Select option: ").strip()
        if choice == "0":
            print("\n  Vault locked. Goodbye.\n")
            break
        elif choice in options:
            _, action = options[choice]
            if action:
                action()
                input("\n  Press Enter to continue...")
        else:
            print("  Invalid option.")


if __name__ == "__main__":
    main()
