#!/bin/sh
set -e

if [ "$#" -eq 0 ]; then
  # 기본값: web 서비스. migrate/collectstatic은 여기서만 돈다 —
  # worker와 동시에 두 번 돌면 스키마 락 경합이 날 수 있어서 web 쪽 책임으로 둔다.
  python manage.py migrate --noinput
  python manage.py collectstatic --noinput
  exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3
fi

# worker 등 다른 커맨드가 docker-compose command:로 넘어온 경우 그대로 실행
exec "$@"
