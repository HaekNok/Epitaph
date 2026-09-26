#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Конфигурация путей выполнения скрипта
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
REQUIRED_PKGS=("python" "git" "clang" "binutils" "make" "libjpeg-turbo" "freetype" "libxml2" "libxslt" "rust")

printf "[QA] Проверка окружения Termux (%s)
" "$(uname -m)"

# Проверка и установка системных пакетов Termux
MISSING_PKGS=()
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    printf "[QA] Установка недостающих пакетов через pkg: %s
" "${MISSING_PKGS[*]}"
    pkg update -y
    pkg install -y "${MISSING_PKGS[@]}"
else
    printf "[QA] Системные пакеты установлены.
"
fi

# Создание изолированного виртуального окружения по стандарту PEP 668
if [ ! -d "${VENV_DIR}" ]; then
    printf "[QA] Создание venv: %s
" "${VENV_DIR}"
    python -m venv "${VENV_DIR}"
fi

# Активация виртуального окружения
source "${VENV_DIR}/bin/activate"

# Ограничение параллелизма сборки для защиты от Android OOM-killer
export CARGO_BUILD_JOBS=2
export RUSTFLAGS="-C lto=no"
export CFLAGS="-Wno-error"

printf "[QA] Обновление базовых утилит pip
"
pip install --upgrade pip setuptools wheel

# Установка проекта в режиме редактирования без опционального Playwright
printf "[QA] Установка Epitaph в режиме editable (pip install -e .)
"
pip install -e "${PROJECT_ROOT}"

# Верификация импорта всех ключевых модулей пакета
printf "[QA] Проверка импортов модулей
"
python -c "
import sys
modules = [
    'epitaph',
    'epitaph.core.limiter',
    'epitaph.core.events',
    'epitaph.core.scheduler',
    'epitaph.core.engine',
    'epitaph.models.base',
    'epitaph.models.target',
    'epitaph.models.proxy',
    'epitaph.models.result',
    'epitaph.network.http_client',
    'epitaph.network.proxy_manager',
    'epitaph.network.circuit_breaker',
    'epitaph.network.browser_pool',
    'epitaph.execution.base',
    'epitaph.reporting.dispatcher',
    'epitaph.ui.app',
    'epitaph.utils.user_agents'
]

failed = []
for mod in modules:
    try:
        __import__(mod)
        print(f'  [OK] {mod}')
    except Exception as err:
        print(f'  [FAIL] {mod}: {err}')
        failed.append(mod)

if failed:
    sys.exit(1)
"

# Запуск юнит-тестов в headless-режиме без интерактивного TUI
printf "[QA] Запуск юнит-тестов pytest
"
if pip show pytest >/dev/null 2>&1; then
    pytest "${PROJECT_ROOT}/tests/unit" -v -m "not browser"
else
    printf "[QA] Пакет pytest не установлен в базовом окружении, шаг пропущен.
"
fi

# Проверка обработки CLI-флагов без аварийного падения
printf "[QA] Проверка CLI точек входа
"
python -m epitaph --help >/dev/null
epitaph --version

printf "[QA] Дымовое тестирование в среде Termux успешно завершено.
"
