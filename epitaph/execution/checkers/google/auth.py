import hashlib
import json
import os
from pathlib import Path
import time
from typing import Dict, Optional
from pydantic import BaseModel, ConfigDict


class GoogleSessionCredentials(BaseModel):
    model_config = ConfigDict(frozen=True)

    sapisid: str
    sid: Optional[str] = None
    ssid: Optional[str] = None
    hsid: Optional[str] = None

    @classmethod
    def get_default_config_path(cls) -> Path:
        return Path.home() / ".epitaph" / "credentials" / "google_session.json"

    @classmethod
    def load_from_storage(cls, config_path: Optional[Path] = None) -> Optional["GoogleSessionCredentials"]:
        env_sapisid = os.environ.get("EPITAPH_GOOGLE_SAPISID")
        if env_sapisid:
            return cls(
                sapisid=env_sapisid.strip(),
                sid=os.environ.get("EPITAPH_GOOGLE_SID"),
                ssid=os.environ.get("EPITAPH_GOOGLE_SSID"),
                hsid=os.environ.get("EPITAPH_GOOGLE_HSID"),
            )

        target = config_path or cls.get_default_config_path()
        if not target.is_file():
            return None

        try:
            with open(target, "r", encoding="utf-8") as f:
                return cls(**json.load(f))
        except Exception:
            return None

    def is_personal_account_detected(self) -> bool:
        """Проверка, является ли сессия потенциально персональным аккаунтом оператора."""
        return os.environ.get("EPITAPH_SOCK_PUPPET_CONFIRMED") != "1"

    def save_to_storage(self, config_path: Optional[Path] = None) -> Path:
        """Безопасное сохранение сессионных куки с правами 0700 на папку и 0600 на файл."""
        target = config_path or self.get_default_config_path()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            target.parent.chmod(0o700)
        except OSError:
            pass

        target.touch(mode=0o600, exist_ok=True)
        try:
            target.chmod(0o600)
        except OSError:
            pass

        with open(target, "w", encoding="utf-8") as f:
            dump_fn = getattr(self, "model_dump", getattr(self, "dict", None))
            json.dump(dump_fn(), f, indent=2)

        return target

    def generate_sapisid_hash(self, origin: str = "https://contacts.google.com") -> str:
        timestamp = str(int(time.time()))
        digest = hashlib.sha1(f"{timestamp} {self.sapisid} {origin}".encode("utf-8")).hexdigest()
        return f"SAPISIDHASH {timestamp}_{digest}"

    def build_headers(self, origin: str = "https://contacts.google.com") -> Dict[str, str]:
        cookies = [f"SAPISID={self.sapisid}"]
        for name, val in [("SID", self.sid), ("SSID", self.ssid), ("HSID", self.hsid)]:
            if val:
                cookies.append(f"{name}={val}")

        return {
            "Authorization": self.generate_sapisid_hash(origin),
            "Cookie": "; ".join(cookies),
            "X-Origin": origin,
            "X-Goog-AuthUser": "0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
