# Diffie-Hellman Key Exchange & Hill Cipher Demo

This repo includes a small web UI for encrypting and decrypting messages using the Hill 2x2 cipher (`lab4_support.py`).

## Run the Web UI (local Python)

Install dependencies (minimal set for the web app):

```bash
pip install -r requirements-web.txt
```

Start the server (default bind: `127.0.0.1`, port **8000**):

```bash
python3 web_app.py
```

Or explicitly:

```bash
python3 web_app.py --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

**Environment overrides (optional):** `WEB_APP_HOST`, `PORT`, or `WEB_APP_PORT` are read before CLI defaults; flags still win when passed.

**Input rules:**

- Messages must be letters A-Z only (no spaces or symbols).
- Keys must be exactly four letters A-Z.
- The key matrix must be invertible modulo 26 (determinant odd and not divisible by 13), or encryption/decryption will fail with an error.

## Run with Docker

Build and run (app listens on **8080** inside the container; host maps **8080→8080** by default):

```bash
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080).

- Change the **host** publish port: `PUBLISH_PORT=3000 docker compose up` → [http://localhost:3000](http://localhost:3000) (container still uses 8080 unless you change `PORT` in compose).
- Bare image: `docker build -t hill-web .` then `docker run --rm -p 8080:8080 hill-web`

## Subdomain deployment

**Security:** This demo has no authentication. Always put **TLS** (HTTPS) and sensible access controls in front of it when exposing a subdomain. Without that, traffic is plaintext.

Typical layout:

1. Run the app on the server (Docker Compose or `python3 web_app.py --host 0.0.0.0 --port <port>`).
2. Point DNS for your subdomain (e.g. `hill.example.com`) at the server.
3. Terminate HTTPS on a reverse proxy and proxy to the app.

An annotated **nginx** example is in [`deploy/subdomain.nginx.conf`](deploy/subdomain.nginx.conf) (defaults to upstream `127.0.0.1:8080` when using the provided Docker setup).
