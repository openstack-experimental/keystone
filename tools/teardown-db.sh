#!/usr/bin/env bash
echo "Stopping databases..."
docker compose -f $PWD/tools/docker-compose.test.yaml down
