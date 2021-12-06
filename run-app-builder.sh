#!/bin/sh
docker run --rm -ti -v "$(realpath .):/app" app-radix-builder:latest
