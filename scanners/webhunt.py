#!/usr/bin/env python3
"""Lanceur autonome de WebHunt.

Permet d'exécuter l'outil sans installation :  python3 webhunt.py <cible>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webhunt.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
