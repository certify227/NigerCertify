"""Point d'entrée : `python -m webhunt`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
