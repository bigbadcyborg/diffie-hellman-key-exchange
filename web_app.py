#!/usr/bin/env python3
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
import argparse

from lab4_support import cipher_decryption, cipher_encryption


ALLOWED_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


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
    <title>Message Encrypt / Decrypt</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 2rem; }}
      .container {{ max-width: 720px; }}
      label {{ display: block; margin-top: 1rem; font-weight: bold; }}
      textarea, input[type="text"] {{ width: 100%; padding: 0.5rem; font-size: 1rem; }}
      .actions {{ margin-top: 1rem; }}
      .actions button {{ padding: 0.6rem 1.2rem; font-size: 1rem; }}
      .result {{ margin-top: 1.5rem; padding: 1rem; background: #f7f7f7; }}
      .error {{ margin-top: 1.5rem; padding: 1rem; background: #ffe4e4; color: #8a1f1f; }}
      .note {{ font-size: 0.9rem; color: #555; margin-top: 0.5rem; }}
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Encrypt / Decrypt Messages</h1>
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


class EncryptHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        self._send_html(render_page())

    def do_POST(self):
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
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
                raise ValueError("Unknown action.")
        except ValueError as exc:
            error = str(exc)

        self._send_html(render_page(message, key, action, result, error))

    def _send_html(self, html):
        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)


def main():
    parser = argparse.ArgumentParser(description="Run the encrypt/decrypt web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), EncryptHandler)
    print(f"Server running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
