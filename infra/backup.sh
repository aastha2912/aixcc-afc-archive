#!/bin/bash -eux
cd /data/influxdb
INFLUX_TOKEN=$(cat /etc/influxdb/operator_token) sudo -E -u influxdb influx backup ./backup

ts=$(date +"%Y-%m-%dT%H.%M.%S%z")
dst_url="${CRS_DEV_BLOB_URL}/historic/auto/$ts-${AZURE_RESOURCE_GROUP}"
for folder in logs data cache influxdb/backup; do
    sudo azcopy sync "/data/${folder}/" "${dst_url}/${folder}/"
done
echo "[+] Backed up to $dst_url"
