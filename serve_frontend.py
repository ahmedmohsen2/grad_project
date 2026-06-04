from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent / "frontend" / "dist"


class SpaHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        candidate = (ROOT / clean).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            return str(ROOT / "index.html")
        if candidate.is_file():
            return str(candidate)
        return str(ROOT / "index.html")

    def log_message(self, format: str, *args):
        return


def main():
    if not (ROOT / "index.html").exists():
        raise SystemExit("frontend/dist/index.html not found. Run npm.cmd run build first.")
    server = ThreadingHTTPServer(("127.0.0.1", 4173), SpaHandler)
    print("Frontend available at http://127.0.0.1:4173")
    server.serve_forever()


if __name__ == "__main__":
    main()
