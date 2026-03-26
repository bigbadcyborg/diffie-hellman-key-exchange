#!/usr/bin/env python3
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import argparse
import base64
import errno
import hashlib
import logging
import sys

from lab4_support import cipher_decryption, cipher_encryption


ALLOWED_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
MAX_BODY_SIZE = 10 * 1024
STYLES = """
body { font-family: Arial, sans-serif; margin: 2rem; }
.container { max-width: 720px; }
label { display: block; margin-top: 1rem; font-weight: bold; }
textarea, input[type="text"] { width: 100%; padding: 0.5rem; font-size: 1rem; }
.actions { margin-top: 1rem; }
.actions button { padding: 0.6rem 1.2rem; font-size: 1rem; }
.result { margin-top: 1.5rem; padding: 1rem; background: #f7f7f7; }
.error { margin-top: 1.5rem; padding: 1rem; background: #ffe4e4; color: #8a1f1f; }
.note { font-size: 0.9rem; color: #555; margin-top: 0.5rem; }
""".strip()
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLES.encode("utf-8")).digest()).decode("utf-8")
logger = logging.getLogger(__name__)


def normalize_message(value):
    cleaned = value.strip().upper()
    if not cleaned:
        raise ValueError("Message cannot be empty.")
    if any(char not in ALLOWED_CHARS for char in cleaned):
        raise ValueError("Message must contain only letters A-Z (no spaces or symbols).")
    return cleaned


def normalize_key(value):
    cleaned = value.strip().upper()
    if len(cleaned) != 4:
        raise ValueError("Key must be exactly 4 letters (A-Z).")
    if any(char not in ALLOWED_CHARS for char in cleaned):
        raise ValueError("Key must contain only letters A-Z.")
    return cleaned


def render_page(message="", key="", action="encrypt", result="", error=""):
    message_value = escape(message)
    key_value = escape(key)
    result_value = escape(result)
    error_value = escape(error)
    encrypt_checked = "checked" if action == "encrypt" else ""
    decrypt_checked = "checked" if action == "decrypt" else ""

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Message Encrypt/Decrypt</title>
    <style>{STYLES}</style>
  </head>
  <body>
    <div class="container">
      <h1>Encrypt/Decrypt Messages</h1>
      <p class="note">Uses the existing Hill 2x2 cipher implementation. Messages and keys must be letters A-Z only.</p>
      <form method="post">
        <label for="message">Message</label>
        <textarea id="message" name="message" rows="4" required>{message_value}</textarea>
        <label for="key">Key (4 letters)</label>
        <input id="key" name="key" type="text" value="{key_value}" maxlength="4" required>
        <div class="actions">
          <label><input type="radio" name="action" value="encrypt" {encrypt_checked}> Encrypt</label>
          <label><input type="radio" name="action" value="decrypt" {decrypt_checked}> Decrypt</label>
        </div>
        <div class="actions">
          <button type="submit">Run</button>
        </div>
      </form>
      {"<div class=\"error\"><strong>Error:</strong> " + error_value + "</div>" if error else ""}
      {"<div class=\"result\"><strong>Result:</strong><pre>" + result_value + "</pre></div>" if result else ""}
    </div>
  </body>
</html>"""


class EncryptDecryptHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        self._send_html(render_page())

    def do_POST(self):
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self.send_error(411, "Content-Length required.")
            return
        try:
            content_length = int(length_header)
        except ValueError:
            self.send_error(400, "Invalid Content-Length header.")
            return
        if content_length > MAX_BODY_SIZE:
            self.send_error(413, "Request body too large.")
            return
        try:
            body = self.rfile.read(content_length).decode("utf-8")
        except UnicodeDecodeError:
            self.send_error(400, "Invalid request encoding.")
            return
        form = parse_qs(body)

        message = form.get("message", [""])[0]
        key = form.get("key", [""])[0]
        action = form.get("action", ["encrypt"])[0]

        result = ""
        error = ""
        try:
            normalized_message = normalize_message(message)
            normalized_key = normalize_key(key)
            if action == "encrypt":
                result = cipher_encryption(normalized_message, normalized_key)
            elif action == "decrypt":
                result = cipher_decryption(normalized_message, normalized_key)
            else:
                raise ValueError("Invalid action. Must be either encrypt or decrypt.")
        except ValueError as exc:
            error = str(exc)
        except Exception as exc:
            logger.error(
                "Unexpected error while processing request: %s: %s",
                type(exc).__name__,
                exc,
            )
            error = "Unexpected error occurred. Please check server logs."

        self._send_html(render_page(message, key, action, result, error))

    def _send_html(self, html):
        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'self'; style-src 'sha256-{STYLE_HASH}'; "
            "form-action 'self'; script-src 'none'",
        )
        self.end_headers()
        self.wfile.write(encoded)


def main():
    parser = argparse.ArgumentParser(description="Run the encrypt/decrypt web UI.")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind (default: 127.0.0.1). Use 0.0.0.0 only behind HTTPS.",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    try:
        server = HTTPServer((args.host, args.port), EncryptDecryptHandler)
    except OSError as exc:
        detail = ""
        if exc.errno == errno.EADDRINUSE:
            detail = "Port already in use."
        elif exc.errno == errno.EACCES:
            detail = "Permission denied. Try a higher port."
        detail_suffix = f" {detail}" if detail else ""
        print(
            f"Unable to start server on {args.host}:{args.port}: "
            f"{type(exc).__name__}: {exc}.{detail_suffix}"
        )
        return 1

    if args.host in {"0.0.0.0", "::"}:
        print(
            f"Server running on http://{args.host}:{args.port} "
            f"(binds to all interfaces; ensure HTTPS when exposed)."
        )
    else:
        print(f"Server running on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
