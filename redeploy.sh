#!/bin/sh
set -ex

#nginx
git pull origin main

docker compose down && docker compose up --build -d 