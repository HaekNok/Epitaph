# Epitaph

Быстрый модульный OSINT-инструмент для поиска аккаунтов по никнейму в терминале.

Основан на событийно-ориентированной архитектуре: сетевой стек (HTTPX + Playwright) вынесен в отдельные асинхронные воркеры и общается с терминальным интерфейсом Textual через очереди `asyncio.Queue`. Благодаря этому интерфейс не зависает при массовых проверках.

## Особенности

- TUI-интерфейс на Textual в палитре Crimson Noir (30 слотов, навигация клавиатурой и мышью, терминальная командная строка).
- Адаптация под мобильные устройства: кнопка принудительного вызова экранной клавиатуры (IME) в Termux и переключение в 1-колоночный режим.
- Асинхронные проверки через HTTP/2 с автоматическим переключением на headless Chromium при наличии Cloudflare или тяжелого клиентского JS.
- Пул прокси (HTTP, HTTPS, SOCKS5) с ротацией и Circuit Breaker: сбойные узлы автоматически отправляются в карантин.
- Экспорт результатов в JSON, CSV, автономный HTML и PDF.

## Установка

Требуется Python 3.11+.

### Linux / macOS

```bash
git clone https://github.com/HaekNok/Epitaph.git
cd Epitaph

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
playwright install chromium  # опционально, для браузерных чекеров
```

### Termux (Android)

Для сборки C/Rust зависимостей (cryptography, reportlab) установите сборочные пакеты:

```bash
pkg update && pkg install -y python git clang build-essential binutils libxml2 libxslt libjpeg-turbo freetype rust
git clone https://github.com/HaekNok/Epitaph.git
cd Epitaph

python -m venv .venv
source .venv/bin/activate

# Важное примечание: начиная со второй версии Pydantic (Rust pydantic-core),
# Termux часто не может собрать пакет из-за ограничений памяти или компилятора.
# Поэтому перед установкой программы рекомендуется выполнить:
pip install "pydantic<2"

pip install -e .
```

*Примечание:* В Termux браузерные чекеры (Playwright) отключаются автоматически, сканер работает в чистом HTTP-режиме.

## Использование

Запуск приложения из активированного виртуального окружения:

```bash
epitaph
```

Или через вызов модуля:

```bash
python -m epitaph
```

### Управление в интерфейсе

- `Кнопка "> клавиатура"` — вызов экранной клавиатуры на смартфонах с фокусом в поле ввода
- `1`-`30` + `Enter` в строке ввода — выбор функционального модуля
- `Клик мышью` или фокус `Tab` + `Enter` — переход по слотам
- `Кнопка "[q] > выход"`, `q` или `Ctrl+C` — выход

## Структура

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

## Тесты

```bash
pytest tests/unit -v
mypy --package epitaph --strict
```
