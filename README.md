# Epitaph

Быстрый модульный OSINT-инструмент для поиска аккаунтов по никнейму в терминале.

Основан на событийно-ориентированной архитектуре: сетевой стек (HTTPX + Playwright) вынесен в отдельные асинхронные воркеры и общается с терминальным интерфейсом Textual через очереди `asyncio.Queue`. Благодаря этому интерфейс не зависает при массовых проверках.

## Особенности

- TUI-интерфейс на Textual в палитре Crimson Noir (30 слотов, навигация клавиатурой и мышью, терминальная командная строка).
- Адаптация под мобильные устройства: кнопка принудительного вызова экранной клавиатуры (IME) в Termux, поддержка Touch-First выбора модулей и автоматическое переключение в 1-колоночный режим.
- Асинхронные проверки через HTTP/2 с автоматическим переключением на headless Chromium при наличии Cloudflare или тяжелого клиентского JS.
- Пул прокси (HTTP, HTTPS, SOCKS5) с ротацией и Circuit Breaker: сбойные узлы автоматически отправляются в карантин.
- Кроссплатформенный экспорт отчетов (JSON, CSV, автономный HTML и PDF) с поддержкой `$TMPDIR` в Android Termux.

## Установка

Требуется Python 3.11+.

### Linux / macOS

```bash
git clone https://github.com/HaekNok/Epitaph.git
cd Epitaph

python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[full]"
playwright install chromium  # опционально, для браузерных чекеров
```

### Termux (Android aarch64)

В Termux браузерные чекеры (Playwright) отключаются автоматически, сканер функционирует в чистом HTTP-режиме без системных сбоев.

1. Установите системные зависимости и компиляторы для сборки C/Rust-пакетов:

```bash
pkg update && pkg install -y python git clang build-essential binutils libxml2 libxslt libjpeg-turbo freetype rust
```

2. Склонируйте репозиторий и создайте виртуальное окружение (в соответствии с PEP 668):

```bash
git clone https://github.com/HaekNok/Epitaph.git
cd Epitaph

python -m venv .venv
source .venv/bin/activate
```

3. Установка Pydantic v2:
Проект строго использует API Pydantic v2 (ConfigDict, model_dump_json, model_copy). Во избежание тяжелой компиляции Rust-пакета pydantic-core и вылетов по OOM, рекомендуется установить готовый бинарный пакет из TUR (Termux User Repository):

```bash
pkg install -y tur-repo
pkg install -y python-pydantic
pip install -e .
```

Альтернативная сборка pydantic-core из исходников (требуется swap от 1 ГБ):

```bash
export CARGO_BUILD_JOBS=2
export RUSTFLAGS="-C lto=no -C opt-level=1"
pip install -e .
```

## Использование и CLI-параметры

Запуск интерактивного TUI:

```bash
epitaph
# или python -m epitaph
```

### Параметры командной строки

- `-h`, `--help` — вывод краткой справки по аргументам
- `-v`, `--version` — вывод версии программы (`Epitaph v0.1.0 (Termux Engine)`)
- `--no-ui` — запуск без TUI-интерфейса (для работы в неинтерактивных терминалах, скриптах и пайплайнах)

### Управление в мобильном интерфейсе

- `Кнопка "> клавиатура"` — временный сброс захвата мыши xterm и передача фокуса в поле ввода для вызова экранной клавиатуры (IME)
- `Касание слота (Touch-First)` — прямой выбор модуля кликом или тапом по экрану без обязательного использования клавиатуры
- `1`-`30` + `Enter` в строке ввода — числовой выбор слота
- `Кнопка "[q] > выход"`, ввод `q` или сочетание `Ctrl+C` — завершение работы

## Структура проекта

```text
epitaph/
├── core/         # Движок, планировщик и шина событий
├── execution/    # Базовый интерфейс и плагины чекеров
├── models/       # Pydantic-контракты данных
├── network/      # HTTPX-клиенты, прокси-менеджер, Circuit Breaker
├── reporting/    # Генерация отчетов (HTML, PDF, JSON, CSV)
├── ui/           # Textual TUI, стили styles.tcss, экраны и виджеты
└── utils/        # Логирование и ротация User-Agent
```

## Тестирование

```bash
pytest tests/unit -v
mypy --package epitaph --strict
```
