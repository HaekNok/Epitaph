import logging
from pathlib import Path
import re
import sys
from typing import Optional

SENSITIVE_PATTERNS = [
    (re.compile(r"://([^:/\s]+):([^@\s]+)@"), r"://\1:***@"),
    (re.compile(r"(password|token|secret|key|api_key)=([^&\s]+)", re.IGNORECASE), r"\1=***"),
    (re.compile(r'("password"|\'password\')\s*:\s*("|\')[^"\']+("|\')', re.IGNORECASE), r'\1: "***"'),
]


def sanitize_log_message(msg: str) -> str:
    # Санитизация сообщений логов для защиты от утечек учетных данных
    for pattern, repl in SENSITIVE_PATTERNS:
        msg = pattern.sub(repl, msg)
    return msg


class SanitizingFormatter(logging.Formatter):
    # Форматтер с фильтрацией учетных данных прокси и токенов
    def format(self, record: logging.LogRecord) -> str:
        record.msg = sanitize_log_message(str(record.msg))
        return super().format(record)


def setup_logger(
    name: str = "epitaph",
    log_file: Optional[Path] = None,
    level: int = logging.INFO,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        formatter = SanitizingFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
