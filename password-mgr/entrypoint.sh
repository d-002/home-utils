#!/bin/bash

# make sure to stop both running programs
cleanup() {
    nginx -s stop
    kill -TERM $uvicorn_pid
    exit 0
}

trap cleanup SIGTERM SIGINT

nginx

cd /home/user/app
gosu user
python -m uvicorn main:app --host 0.0.0.0 --port 8000
uvicorn_pid=$!

wait $uvicorn_pid
