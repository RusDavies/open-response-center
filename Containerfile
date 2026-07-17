FROM python:3.13-slim

ENV DJANGO_DEBUG=false \
    DJANGO_MEDIA_ROOT=/app/data/uploads \
    DJANGO_SQLITE_PATH=/app/data/db.sqlite3 \
    DJANGO_STATIC_ROOT=/app/staticfiles \
    OPENCLAW_WORKSPACE_ROOT=/workspace \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && mkdir -p /app/data /app/staticfiles /workspace \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app /workspace

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn open_response_center.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-2} --access-logfile - --error-logfile -"]
