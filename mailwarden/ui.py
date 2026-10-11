"""Small terminal UI helpers (colour only when the console actually supports it)."""

from __future__ import annotations

import os
import sys

from .models import DomainAssessment, Severity, UnauthorizedUse
from .risk_engine import RiskScore

_CODES = {"red": "31", "yellow": "33", "green": "32", "blue": "34", "grey": "90", "bold": "1"}


def _enable_windows_vt() -> bool:
    """On Windows, ANSI colour codes only render if the console opts in to VT
    processing. Older consoles (and some terminal hosts) never opt in, and then
    print the raw escape codes as text. Try to turn it on for both stdout and
    stderr; if anything about that fails, we must not emit colour codes at all.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        ENABLE_VT = 0x0004
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = k.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if not k.SetConsoleMode(handle, mode.value | ENABLE_VT):
                return False
        return True
    except Exception:
        return False


_VT_OK = _enable_windows_vt()


def _on() -> bool:
    return (_VT_OK and sys.stdout.isatty() and sys.stderr.isatty()
            and "NO_COLOR" not in os.environ)


def paint(text: str, color: str) -> str:
    return f"\033[{_CODES[color]}m{text}\033[0m" if _on() else text


def step(msg: str) -> None:
    print(paint("==>", "blue"), msg, file=sys.stderr)


def _verdict(a: DomainAssessment) -> str:
    vs = {rp.unauthorized_use_possible for rp in a.relay_paths}
    for v, color in ((UnauthorizedUse.CONFIRMED, "red"), (UnauthorizedUse.SUSPECTED, "yellow")):
        if v in vs:
            return paint(v.value, color)
    if UnauthorizedUse.NOT_ESTABLISHED in vs:
        return paint("not_established", "green")
    return paint("not_assessed", "grey")


def summary_table(rows: list[tuple[DomainAssessment, RiskScore]]) -> str:
    head = ("Domain", "Score", "Crit", "High", "Med", "Relay use", "Gaps")
    data = []
    for a, s in rows:
        n = lambda sev: sum(1 for f in a.findings if f.severity == sev)  # noqa: E731
        data.append((a.domain, f"{s.total} ({s.grade if s.complete else 'partial'})", str(n(Severity.CRITICAL)),
                     str(n(Severity.HIGH)), str(n(Severity.MEDIUM)), _verdict(a),
                     str(len(s.coverage_gaps))))
    plain = lambda t: __import__("re").sub(r"\033\[[0-9;]*m", "", t)  # noqa: E731
    widths = [max(len(plain(r[i])) for r in [head, *data]) for i in range(len(head))]
    line = lambda r: "  ".join(c + " " * (w - len(plain(c))) for c, w in zip(r, widths))  # noqa: E731
    return "\n".join([paint(line(head), "bold"), "  ".join("-" * w for w in widths), *map(line, data)])
