"""Модуль экспорта результатов сессии сканирования в автономный киберпанк HTML-отчет."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from epitaph.models.base import DetectionStatus
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter


class HtmlReportExporter(BaseReportExporter):
    """Экспортер сессии в автономный интерактивный HTML-документ стиля Crimson Noir."""

    @property
    def format_name(self) -> str:
        return "html"

    def _prepare_context(self, data: ScanSessionResult) -> Dict[str, Any]:
        # Расчет длительности сессии сканирования и фильтрация результатов
        duration_sec = max(0.0, (data.end_time - data.start_time).total_seconds())
        found_results = [r for r in data.results if r.status == DetectionStatus.FOUND]
        other_results = [r for r in data.results if r.status != DetectionStatus.FOUND]

        # Извлечение артефактов глубокой разведки Google
        google_data: Optional[Dict[str, Any]] = None
        for r in data.results:
            if r.platform_name == "Google" and r.extracted_data and r.extracted_data.get("gaia_id"):
                google_data = dict(r.extracted_data)
                break

        # Определение целевого адреса электронной почты
        target_email: Optional[str] = None
        if "@" in data.target.username:
            target_email = data.target.username
        elif data.target.metadata.get("email"):
            target_email = str(data.target.metadata.get("email"))
        elif google_data and google_data.get("email"):
            target_email = str(google_data.get("email"))
        else:
            for r in data.results:
                if r.extracted_data.get("email"):
                    target_email = str(r.extracted_data.get("email"))
                    break

        # Определение аватара цели с проверкой безопасного сетевого протокола
        target_avatar: Optional[str] = None
        raw_avatar = data.target.metadata.get("avatar_url")
        if not raw_avatar and google_data:
            raw_avatar = google_data.get("avatar_url")
        if not raw_avatar:
            for r in data.results:
                if r.extracted_data.get("avatar_url"):
                    raw_avatar = r.extracted_data.get("avatar_url")
                    break
        if raw_avatar and isinstance(raw_avatar, str) and (raw_avatar.startswith("http://") or raw_avatar.startswith("https://")):
            target_avatar = raw_avatar

        # Определение отображаемого имени субъекта разведки
        target_display_name: Optional[str] = None
        if data.target.metadata.get("display_name"):
            target_display_name = str(data.target.metadata.get("display_name"))
        elif google_data and google_data.get("display_name"):
            target_display_name = str(google_data.get("display_name"))

        # Вычисление статуса верификации цели
        if data.found_count >= 5:
            verification_status = {
                "title": "ЦЕЛЬ ВЕРИФИЦИРОВАНА",
                "code": "verified",
                "color": "#16A765",
                "badge_class": "status-verified",
            }
        elif data.found_count > 0:
            verification_status = {
                "title": "АКТИВНЫЙ ЦИФРОВОЙ СЛЕД",
                "code": "partial",
                "color": "#F2C960",
                "badge_class": "status-partial",
            }
        else:
            verification_status = {
                "title": "ЦИФРОВОЙ СЛЕД НЕ ОБНАРУЖЕН",
                "code": "clean",
                "color": "#7B8294",
                "badge_class": "status-clean",
            }

        # Определение категориальных тегов профиля по типам платформ
        found_platforms = {r.platform_name.lower() for r in found_results}
        tags: List[str] = []
        if any(p in found_platforms for p in ["github", "gitlab", "bitbucket", "stackoverflow", "codeberg", "npm", "pypi"]):
            tags.append("РАЗРАБОТКА ПО")
        if any(p in found_platforms for p in ["telegram", "x", "twitter", "reddit", "vk", "instagram", "linkedin", "tiktok"]):
            tags.append("СОЦИАЛЬНЫЙ СЛЕД")
        if any(p in found_platforms for p in ["steam", "discord", "twitch", "epic games", "roblox"]):
            tags.append("ИГРОВОЙ ПРОФИЛЬ")
        if any(p in found_platforms for p in ["google", "gmail", "mail.ru", "yandex", "protonmail"]):
            tags.append("ПОЧТОВАЯ СИСТЕМА")
        if any(p in found_platforms for p in ["youtube", "spotify", "soundcloud", "vimeo"]):
            tags.append("МЕДИА И СТРИМИНГ")
        if not tags:
            tags.append("ОБЩИЙ ЦИФРОВОЙ СЛЕД" if data.found_count > 0 else "СЛЕД ОТСУТСТВУЕТ")

        # Агрегация данных о скомпрометированных базах и утечках
        breach_raw = data.target.metadata.get("breaches") or []
        if not breach_raw:
            for r in data.results:
                if "breach" in r.platform_name.lower() and r.extracted_data.get("breaches"):
                    breach_raw = r.extracted_data.get("breaches")
                    break
        db_count = len(breach_raw) if isinstance(breach_raw, list) else int(data.target.metadata.get("breach_count", 0))
        rec_count = sum(b.get("pwn_count", 0) for b in breach_raw) if isinstance(breach_raw, list) and breach_raw and isinstance(breach_raw[0], dict) else int(data.target.metadata.get("breach_records_count", 0))

        if db_count >= 3 or rec_count >= 1000:
            breach_level = "CRITICAL"
            breach_color = "#CC3A21"
        elif db_count > 0:
            breach_level = "HIGH"
            breach_color = "#F2C960"
        else:
            breach_level = "CLEAN"
            breach_color = "#16A765"

        breach_metrics = {
            "databases_count": db_count,
            "records_count": rec_count,
            "risk_level": breach_level,
            "risk_color": breach_color,
            "breaches": breach_raw if isinstance(breach_raw, list) else [],
        }

        # Сетевые артефакты и инфраструктура хоста
        network_artifacts = data.target.metadata.get("network") or []
        if not isinstance(network_artifacts, list):
            network_artifacts = []

        # Аффилиации, связанные контакты и криптокошельки
        raw_affiliations = data.target.metadata.get("affiliations") or {}
        affiliations = {
            "contacts": raw_affiliations.get("contacts", [target_email] if target_email else []),
            "communities": raw_affiliations.get("communities", []),
            "crypto_wallets": raw_affiliations.get("crypto_wallets", []),
        }

        # Геолокационные маркеры и метаданные EXIF
        geo_data = data.target.metadata.get("geo")
        if not geo_data and google_data:
            tz = google_data.get("calendar_timezone")
            reviews = google_data.get("maps_reviews_count", 0)
            if tz or reviews:
                geo_data = {
                    "location_name": tz or "Регион активности Google Maps",
                    "source": "Google Calendar / Maps API",
                    "coordinates": google_data.get("coordinates", "Координаты не зафиксированы"),
                    "accuracy_radius": f"Часовой пояс: {tz}" if tz else "Городская агломерация",
                }

        # Расчет индикаторов рисков и экспозиции данных
        if data.found_count == 0 and db_count == 0:
            exposure_score = 5
        else:
            exposure_score = min(98, 15 + data.found_count * 10 + (20 if target_email else 0) + (10 if target_avatar else 0) + (db_count * 15))

        if exposure_score >= 75:
            exp_level, exp_color = "КРИТИЧЕСКИЙ", "#CC3A21"
        elif exposure_score >= 45:
            exp_level, exp_color = "ВЫСОКИЙ", "#F2C960"
        elif exposure_score >= 20:
            exp_level, exp_color = "УМЕРЕННЫЙ", "#4A86E8"
        else:
            exp_level, exp_color = "НИЗКИЙ", "#16A765"

        infra_score = 75
        if target_email and "@gmail.com" in target_email:
            infra_score -= 15
        if db_count > 0:
            infra_score -= 25
        infra_score = max(10, min(95, infra_score))

        if infra_score >= 70:
            inf_level, inf_color = "ВЫСОКИЙ", "#16A765"
        elif infra_score >= 40:
            inf_level, inf_color = "УМЕРЕННЫЙ", "#F2C960"
        else:
            inf_level, inf_color = "УЯЗВИМЫЙ", "#CC3A21"

        privacy_score = max(5, min(95, 100 - exposure_score + 5))
        if privacy_score >= 70:
            priv_level, priv_color = "НАДЕЖНЫЙ", "#16A765"
        elif privacy_score >= 40:
            priv_level, priv_color = "УМЕРЕННЫЙ", "#F2C960"
        else:
            priv_level, priv_color = "СКОМПРОМЕТИРОВАН", "#CC3A21"

        risk_scores = {
            "data_exposure": {"score": exposure_score, "level": exp_level, "color": exp_color},
            "infra_protection": {"score": infra_score, "level": inf_level, "color": inf_color},
            "privacy_opsec": {"score": privacy_score, "level": priv_level, "color": priv_color},
        }

        # Формирование хронологического таймлайна событий сессии
        timeline_events: List[Dict[str, str]] = []
        timeline_events.append({
            "timestamp": data.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": "Инициализация поисковой сессии Epitaph",
            "category": "SYSTEM",
            "description": f"Запуск пула воркеров для цели @{data.target.username}",
        })
        for r in found_results:
            timeline_events.append({
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "title": f"Обнаружен профиль: {r.platform_name}",
                "category": "DISCOVERY",
                "description": f"Зафиксирован активный сетевой след, отклик {r.response_time_ms:.1f} мс",
            })
        timeline_events.append({
            "timestamp": data.end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "title": "Завершение опроса сервисов и компиляция отчета",
            "category": "SYSTEM",
            "description": f"Обработано {data.total_scanned} сервисов, выявлено {data.found_count} профилей",
        })

        # Вычисление контрольного хэша сессии досье
        hash_raw = f"{data.session_id}:{data.target.username}:{data.start_time.isoformat()}"
        session_hash = hashlib.sha256(hash_raw.encode("utf-8")).hexdigest()[:32].upper()

        return {
            "data": data,
            "session_id": data.session_id,
            "target": data.target,
            "session_duration": f"{duration_sec:.2f}s",
            "verification_status": verification_status,
            "target_email": target_email,
            "target_avatar": target_avatar,
            "target_display_name": target_display_name,
            "profile_tags": tags,
            "breach_metrics": breach_metrics,
            "found_results": found_results,
            "other_results": other_results,
            "network_artifacts": network_artifacts,
            "affiliations": affiliations,
            "geo_data": geo_data,
            "google_data": google_data,
            "risk_scores": risk_scores,
            "timeline_events": timeline_events,
            "session_hash": session_hash,
            "generation_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    def _render_sync(self, data: ScanSessionResult, output_path: Path) -> Path:
        # Синхронный рендеринг HTML-шаблона для вызова в отдельном потоке
        template_dir = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")
        context = self._prepare_context(data)
        rendered = template.render(**context)
        output_path.write_text(rendered, encoding="utf-8")
        return output_path

    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        # Рендеринг шаблона Jinja2 выносится в отдельный поток во избежание подвисания TUI
        return await asyncio.to_thread(self._render_sync, data, output_path)
