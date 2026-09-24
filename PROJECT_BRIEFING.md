# Архитектурный контекст и спецификация проекта Epitaph

Документ предназначен для передачи контекста AI-агентам, архитекторам и разработчикам для погружения в кодовую базу, архитектурные слои, модель данных и платформенные ограничения проекта Epitaph.

---

## 1. Общие сведения и назначение

* **Название проекта**: Epitaph
* **Репозиторий**: `https://github.com/HaekNok/Epitaph`
* **Назначение**: Высокопроизводительный модульный OSINT-инструмент для асинхронного поиска профилей по никнейму на множестве интернет-платформ с терминальным интерфейсом (TUI) и поддержкой работы на мобильных устройствах (Android Termux).
* **Стек технологий**:
  - Язык: Python 3.11+
  - TUI-фреймворк: Textual
  - Сетевой стек: HTTPX (HTTP/2, connection pooling)
  - Headless браузер: Playwright (Chromium, опциональный компонент)
  - Валидация данных: Pydantic v2 (`pydantic>=2.7.0`)
  - Экспорт отчетов: Jinja2 (HTML), ReportLab (PDF), aiofiles (JSON, TXT, CSV)
  - Сборка: Hatchling (pyproject.toml, PEP 517/621)
  - Линтеры и тесты: Ruff, Mypy (strict mode), Pytest (pytest-asyncio)

---

## 2. Архитектурный паттерн и поток данных

В основе Epitaph лежит **Event-Driven Modular Monolith (Событийно-ориентированный модульный монолит)**.

### Главный инженерный принцип
Полная изоляция Presentation Layer (Textual TUI) от Network & Execution I/O. Никаких сетевых вызовов, блокирующего рендеринга или тяжелых вычислений в главном потоке интерфейса:
- UI подписывается на асинхронную очередь `asyncio.Queue[Any]` движка `ScanEngine`.
- Фоновые воркеры опрашивают платформы и отправляют события (`CheckResultEvent`, `ProgressUpdateEvent`, `ScanCompletedEvent`).
- UI вычитывает события и реактивно обновляет виджеты, не блокируя цикл обработки событий терминала.

### Поток данных (Data Flow)
```text
[ Пользователь / CLI / Touch ]
               │
               ▼
      [ MainScreen (Textual) ]
               │  (Запуск сканирования)
               ▼
      [ ScanEngine (Core) ]
               │
     ┌─────────┴───────────────────────┐
     │                                 │
     ▼                                 ▼
[ TaskScheduler ]              [ event_queue ]
     │ (Semaphore)                     │
     ├─► [ DomainRateLimiter ]         │
     ├─► [ ProxyManager / CircuitBreaker ]
     │                                 │
     ▼                                 │
[ BasePlatformChecker ]                │
  ├── check_http() ──► HTTPX           │
  └── check_browser() ─► Playwright    │
               │                       │
               └──── CheckResult ─────►│
                                       │
                                       ▼
                             [ TUI Event Consumer ]
                             (Отображение прогресса)
                                       │
                                       ▼
                             [ ReportDispatcher ]
                             ├── JSON Export (aiofiles)
                             ├── TXT Export (aiofiles)
                             ├── HTML Export (Jinja2 + thread)
                             └── PDF Export (ReportLab + thread)
```

---

## 3. Детализация слоев системы

### 3.1. Presentation Layer (`epitaph/ui/`)
* **Визуальный стиль**: Палитра *Crimson Noir* (глубокий черный фон `#02060E`, акцентный бордовый `#C50337`, приглушенный винный `#8B1E3F`, светлый текст `#D4D7DD`).
* **Адаптивность (Responsive Grid)**:
  - Терминалы >= 80 колонок: 3-колоночная сетка на 30 слотов модулей (`#grid_container`).
  - Терминалы < 80 колонок: автоматическое переключение в класс `.compact-layout` (1 вертикальная колонка).
* **Адаптивный баннер (`epitaph/ui/widgets/banner.py`)**:
  - Ширина >= 60 колонок: отображение полноразмерного ASCII-баннера `ASCII_BANNER_FULL`.
  - Ширина < 60 колонок: компактный баннер `ASCII_BANNER_COMPACT` (38 символов) во избежание переноса строк.
* **Мобильный ввод и обход ограничений Termux IME (`epitaph/ui/screens/main_screen.py`)**:
  - Кнопка `> клавиатура` временно отключает захват мыши escape-последовательностью `[?1000l[?1002l[?1003l[?1006l` через `self.app._driver.write()`, передает фокус в `command_input` и ставит курсор в конец строки. Последующий тап по экрану открывает клавиатуру Android.
  - Включен неблокирующий таймер отката на 3 секунды (`self.set_timer(3.0, self._restore_mouse_tracking)`) и мгновенный сброс на первом вводе символа (`Input.Changed`).
  - Touch-First интерфейс: слоты меню реагируют на событие `MenuSlot.Selected` прямым касанием.

### 3.2. Core & Orchestration Layer (`epitaph/core/`)
* **`ScanEngine`**: Инициализирует очереди сессий, связывает чекеры с диспетчером отчетов, публикует события без утечек памяти.
* **`TaskScheduler`**: Ограничивает параллелизм через `asyncio.Semaphore(max_concurrent_workers)`. Реализует ленивый доступ к пулу браузеров `@property browser_pool`.
* **`DomainRateLimiter`**: Хранит историю обращений к доменам и локальные блокировки `asyncio.Lock`.

### 3.3. Execution Layer (`epitaph/execution/`)
* **Базовый контракт (`epitaph/execution/base.py`)**:
  - Класс `BasePlatformChecker`: поля `name`, `execution_type` (`HTTP` или `BROWSER`), `rate_limit_delay`.
  - Методы `check_http` и `check_browser` возвращают детерминированный `CheckResult` (`DetectionStatus.BLOCKED`, `DetectionStatus.ERROR`), не пробрасывая `NotImplementedError`.
* **Реестр плагинов**: Автоматическая регистрация чекеров через декоратор `@register_checker`.

### 3.4. Network & Resilience Layer (`epitaph/network/`)
* **`HttpClientManager`**: Управляет пулом постоянных соединений `httpx.AsyncClient` с включенным HTTP/2.
* **`PlaywrightBrowserPool`**:
  - Безопасный lazy-импорт: защищен блоком `try...except (ImportError, RuntimeError)` с выставлением флага `HAS_PLAYWRIGHT`.
* **`ProxyManager` и `CircuitBreaker`**:
  - Поддержка HTTP, HTTPS, SOCKS5.
  - Ротация Round-Robin со взвешиванием по пингу, карантин на 300 секунд.

### 3.5. Reporting Layer (`epitaph/reporting/`)
* **`ReportDispatcher`**: Параллельный экспорт через `asyncio.TaskGroup`.
* **Кроссплатформенные пути (`get_default_report_dir`)**:
  - Исключены жестко зашитые пути `/tmp`. Используется переменная `$TMPDIR` с фоллбэком на `tempfile.gettempdir()`.

### 3.6. Entry Points (`epitaph/main.py`, `epitaph/__main__.py`)
* Канонический запуск: `python -m epitaph` вызывает `sys.exit(main())`.
* CLI-аргументы (`argparse`): `--no-ui`, `--version`, `--help`.

---

## 4. Специфика мобильного окружения (Android Termux aarch64)

1. **Бинарный Pydantic v2**: Установка из репозитория TUR: `pkg install -y tur-repo && pkg install -y python-pydantic`.
2. **Чистый HTTP-режим**: В Termux Playwright отключается автоматически, все чекеры работают стабильно.
3. **PEP 668**: Рекомендуется создание виртуального окружения `python -m venv .venv && source .venv/bin/activate`.
