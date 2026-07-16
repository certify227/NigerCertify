"""WebHunt - Boîte à outils de reconnaissance et d'audit de vulnérabilités web.

Outil pédagogique et éthique destiné au bug bounty et aux tests d'intrusion
AUTORISÉS. L'utilisation contre un système sans permission écrite est illégale.
"""

__version__ = "1.0.0"
__author__ = "Niger Certify Offensive Lab"

from .findings import Finding, Severity  # noqa: F401
from .scope import Scope  # noqa: F401
from .http_client import HttpClient  # noqa: F401
