# Точка входа в приложение Epitaph с обработкой аргументов командной строки
import argparse
import sys
from epitaph import __version__
from epitaph.ui.app import EpitaphApp


def create_parser() -> argparse.ArgumentParser:
    # Инициализация парсера аргументов командной строки
    parser = argparse.ArgumentParser(
        prog="epitaph",
        description="Модульный асинхронный OSINT-инструмент для поиска профилей.",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Запуск сканера без интерактивного TUI-интерфейса",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"Epitaph v{__version__} (Termux Engine)",
    )
    return parser


def main() -> None:
    # Главная функция запуска с проверкой CLI-флагов и интерактивного терминала
    parser = create_parser()
    args, unknown = parser.parse_known_args()

    if args.no_ui:
        sys.stdout.write("Epitaph CLI: запуск без TUI завершен.
")
        return

    # Проверка наличия интерактивного TTY во избежание сбоев драйвера Textual
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.stderr.write(
            "Ошибка: TUI требует интерактивного TTY-терминала. Запустите с флагом --no-ui.
"
        )
        sys.exit(1)

    EpitaphApp().run()


if __name__ == "__main__":
    main()
