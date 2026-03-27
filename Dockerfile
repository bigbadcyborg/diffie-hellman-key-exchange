FROM python:3.12-slim-bookworm

WORKDIR /app

COPY requirements-web.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY web_app.py lab4_support.py ./

RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV WEB_APP_HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["python", "web_app.py"]
