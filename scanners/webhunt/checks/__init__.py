"""Modules de détection de vulnérabilités de WebHunt.

Chaque check implémente l'interface :class:`base.BaseCheck`. Les checks
« passifs » n'envoient pas de charge utile potentiellement intrusive ;
les checks « actifs » envoient des payloads non destructifs et ne
s'exécutent qu'après confirmation d'autorisation.
"""

from __future__ import annotations

from typing import List, Type

from .base import BaseCheck, CheckContext
from .security_headers import SecurityHeadersCheck
from .cookies import CookieCheck
from .cors import CorsCheck
from .info_disclosure import InfoDisclosureCheck
from .open_redirect import OpenRedirectCheck
from .reflected_xss import ReflectedXssCheck
from .http_methods import HttpMethodsCheck

ALL_CHECKS: List[Type[BaseCheck]] = [
    SecurityHeadersCheck,
    CookieCheck,
    CorsCheck,
    InfoDisclosureCheck,
    HttpMethodsCheck,
    OpenRedirectCheck,
    ReflectedXssCheck,
]

__all__ = ["BaseCheck", "CheckContext", "ALL_CHECKS"]
