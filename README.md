# Diffie-Hellman Key Exchange Demo

This repo now includes a small web UI for encrypting and decrypting messages using the existing Hill 2x2 cipher logic.

## Run the Web UI

Install the Python dependency:

```bash
pip install numpy
```

```bash
python3 web_app.py --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000` in your browser.

**Input rules:**
- Messages must be letters A-Z only (no spaces or symbols).
- Keys must be exactly 4 letters (A-Z).

## Using a Subdomain

Deploy the server on a public host (or behind a reverse proxy) and point your DNS subdomain to that host. For example, bind the app to `0.0.0.0` so it can receive traffic:

```bash
python3 web_app.py --host 0.0.0.0 --port 8000
```

Then configure your web server or hosting platform to route your subdomain (e.g. `crypto.example.com`) to that port.
