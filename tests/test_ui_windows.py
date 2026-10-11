"""ui.py must never leak raw ANSI escape codes when colour can't actually render."""

from mailwarden import ui


def test_enable_windows_vt_is_a_noop_true_on_non_windows():
    # os.name is 'posix' in this test environment, so the Windows-only branch
    # should never run and the function should simply report "colour is fine".
    assert ui._enable_windows_vt() is True


def test_on_requires_vt_ok_and_both_streams_tty(monkeypatch):
    monkeypatch.setattr(ui, "_VT_OK", False)
    monkeypatch.setattr(ui.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(ui.sys.stderr, "isatty", lambda: True)
    assert ui._on() is False  # VT not confirmed working -> never emit escape codes


def test_paint_returns_plain_text_when_off(monkeypatch):
    monkeypatch.setattr(ui, "_on", lambda: False)
    assert ui.paint("hello", "blue") == "hello"


def test_paint_wraps_in_escape_codes_when_on(monkeypatch):
    monkeypatch.setattr(ui, "_on", lambda: True)
    assert ui.paint("hello", "blue") == "\033[34mhello\033[0m"
