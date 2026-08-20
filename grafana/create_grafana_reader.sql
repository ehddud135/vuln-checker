-- Grafana 전용 읽기 전용 Postgres 롤 생성. docker-compose 스택을 처음 띄운 뒤 한 번만 실행:
--
--   source .env
--   docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" << EOF
--   $(cat grafana/create_grafana_reader.sql | envsubst)
--   EOF
--
-- 최소 권한 원칙 — 쓰기 권한은 절대 주지 않는다(design doc/plan.md에서 반복된 원칙과 동일).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grafana_reader') THEN
    CREATE ROLE grafana_reader WITH LOGIN PASSWORD '${GRAFANA_DB_READER_PASSWORD}';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON monitor_metricsample, monitor_host, monitor_checkrun TO grafana_reader;
