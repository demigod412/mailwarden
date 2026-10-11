"""Serve a report directory on localhost only."""

from __future__ import annotations

import functools
import http.server
import webbrowser
from pathlib import Path


class _Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args) -> None:  # quiet
        pass


def serve(directory: Path, port: int = 8765, open_browser: bool = True) -> None:
    handler = functools.partial(_Handler, directory=str(directory))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as srv:
        url = f"http://127.0.0.1:{port}/summary.html"
        print(f"Serving {directory} at {url}  (Ctrl+C to stop)")
        if open_browser:
            webbrowser.open(url)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
