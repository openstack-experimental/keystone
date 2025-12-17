#!/usr/bin/env bash
DB_TYPE=$1 # "postgres" or "mysql"

echo "Starting $DB_TYPE container..."
docker compose -f tools/docker-compose.test.yaml up -d "$DB_TYPE"

if [ "$DB_TYPE" == "postgres" ]; then
    until docker exec $(docker compose -f tools/docker-compose.test.yaml ps -q postgres) pg_isready; do
        sleep 1
    done
    echo "DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/postgres" >> "$NEXTEST_ENV"
else
    until docker exec $(docker compose -f tools/docker-compose.test.yaml ps -q mysql) mysqladmin ping -h"localhost" --silent; do
        sleep 1
    done
    sleep 5;
    echo "DATABASE_URL=mysql://root@127.0.0.1:3306" >> "$NEXTEST_ENV"
fi

