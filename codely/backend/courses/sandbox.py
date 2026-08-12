"""Exécution Python sécurisée pour les exercices de code."""

import re
import subprocess
import tempfile
from pathlib import Path

FORBIDDEN_PATTERNS = [
    r"\bimport\s+os\b",
    r"\bimport\s+sys\b",
    r"\bimport\s+subprocess\b",
    r"\bimport\s+shutil\b",
    r"\bimport\s+socket\b",
    r"\bimport\s+requests\b",
    r"\bfrom\s+os\b",
    r"\bfrom\s+sys\b",
    r"\bfrom\s+subprocess\b",
    r"__import__",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bopen\s*\(",
    r"\bcompile\s*\(",
    r"\bglobals\s*\(",
    r"\blocals\s*\(",
]

MAX_CODE_LENGTH = 2000
TIMEOUT_SECONDS = 5


class SandboxError(Exception):
    pass


def validate_code(code: str) -> None:
    if not code or not code.strip():
        raise SandboxError("Le code ne peut pas être vide.")
    if len(code) > MAX_CODE_LENGTH:
        raise SandboxError(f"Code trop long (max {MAX_CODE_LENGTH} caractères).")
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, code):
            raise SandboxError("Code non autorisé : imports ou fonctions dangereuses interdits.")


def run_python(code: str, stdin: str = "") -> dict:
    """
    Exécute du Python dans un sous-processus isolé.
    Retourne {stdout, stderr, exit_code, success}.
    """
    validate_code(code)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        result = subprocess.run(
            ["python3", temp_path],
            input=stdin.encode() if stdin else None,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            text=False,
        )
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        raise SandboxError(f"Temps d'exécution dépassé ({TIMEOUT_SECONDS}s).")
    finally:
        Path(temp_path).unlink(missing_ok=True)


def check_code_output(code: str, expected_output: str) -> dict:
    """Exécute le code et compare la sortie standard."""
    result = run_python(code)
    expected = expected_output.strip()
    actual = result["stdout"].strip()
    is_correct = result["success"] and actual == expected
    return {
        **result,
        "correct": is_correct,
        "expected": expected,
        "actual": actual,
    }
