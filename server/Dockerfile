FROM python:3.13-slim

# psycopg2-binary는 wheel로 오지만 libpq가 런타임에 필요한 배포판도 있어 명시적으로 설치
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    DJANGO_DEBUG=false

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
