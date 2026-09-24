# Точка входа для запуска пакета как модуля через python -m epitaph
import sys
from epitaph.main import main

if __name__ == "__main__":
    sys.exit(main())
