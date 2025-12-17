#!/usr/bin/env bash
echo "Stopping databases..."
docker compose -f tools/docker-compose.test.yaml stop
