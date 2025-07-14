#!/bin/bash

source .env
export AWS_SECRET_ACCESS_KEY
export AWS_ACCESS_KEY_ID
export AWS_DEFAULT_REGION

POLL_PERIOD=${1:-120}

echo "POLL_PERIOD=$POLL_PERIOD"
while true; do
    aws s3 sync s3://theori-crs-eval-logs ./logs
    ./process_logs.py
    sleep $POLL_PERIOD
done
