# Точка входа для запуска пакета через CLI и команду epitaph
import argparse
import sys
from epitaph.ui.app import EpitaphApp


def main() -> None:
    # Парсинг базовых CLI-аргументов и запуск терминального интерфейса
    parser = argparse.ArgumentParser(
        prog="epitaph",
        description="Модульный OSINT-инструмент поиска аккаунтов по никнейму.",
    )
    parser.add_argument(
        "--version", action="version", version="Epitaph 0.1.0 (Termux Engine)"
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Запуск в неинтерактивном headless-режиме",
    )

    args, _ = parser.parse_known_args()

    if args.no_ui:
        sys.stdout.write("Epitaph готов к работе в фоновом режиме.\n")
        return

    EpitaphApp().run()


if __name__ == "__main__":
    main()
