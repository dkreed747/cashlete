FROM python:3.9-slim AS base
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    FLASK_APP=src/app.py \
    FLASK_ENV=production

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
                rm -f requirements.txt

FROM base AS release

COPY src/ ./src/

RUN mkdir -p /data
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "src.app:app"]

