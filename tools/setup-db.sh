#!/usr/bin/env bash
#set -e

# Default to postgres if no argument is provided
DB_TYPE=${1:-postgres}
COMPOSE_FILE="tools/docker-compose.test.yaml"
#CMD=$(command -v podman 2>/dev/null || command -v docker)
CMD=docker

if [[ "$DB_TYPE" != "postgres" && "$DB_TYPE" != "mysql" ]]; then
    echo "Usage: $0 [postgres|mysql]"
    exit 1
fi

echo "Starting $DB_TYPE container..."
$CMD compose -f $PWD/"$COMPOSE_FILE" up -d "$DB_TYPE"

# Find the container Name by the compose service label
TARGET=$($CMD ps --filter "label=com.docker.compose.service=$DB_TYPE" --format "{{.Names}}" | head -n 1)

if [ -z "$TARGET" ]; then
    echo "Error: Could not find $DB_TYPE container."
    exit 1
fi

echo "Waiting for $DB_TYPE ($TARGET) to be ready..."

if [ "$DB_TYPE" == "postgres" ]; then
    # Postgres check
    until $CMD exec "$TARGET" pg_isready -U postgres > /dev/null 2>&1; do
        printf "."
        sleep 3
    done
    echo "DATABASE_URL=postgres://postgres:password@127.0.0.1:15432/postgres" >> "$NEXTEST_ENV"
else
    ## MySQL check
    until $CMD exec "$TARGET" mysqladmin ping -u root -p'password' --silent ; do
      printf "."
      sleep 1
    done
    
    echo -e "\nMySQL temporary server detected. Waiting for final restart..."
    
    until $CMD logs "$TARGET" 2>&1 | grep -q "Shutting down mysqld"; do
        printf "s"
        sleep 1
    done
    
    # 3. Now wait for the FINAL server to be ready.
    echo -e "\nInitialization finished. Waiting for final server..."
    until $CMD exec "$TARGET" mysql -u root -p'password' -e "SELECT 1" > /dev/null 2>&1; do
        printf "."
        sleep 1
    done
    echo "DATABASE_URL=mysql://root:password@127.0.0.1:13306" >> "$NEXTEST_ENV"
fi

echo -e "\n$DB_TYPE is up and running!"
