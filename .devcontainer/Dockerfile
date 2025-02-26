FROM python:3.9-slim as base
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    FLASK_APP=app.py

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
                rm -f requirements.txt

FROM base as release

COPY src/. .
COPY templates .

RUN mkdir -p /data
EXPOSE 5000

ENTRYPOINT ["flask", "run", "--host=0.0.0.0"]

