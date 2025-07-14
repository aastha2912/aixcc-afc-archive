#!/bin/bash -eux

INFLUX_ORG="theori"
INFLUX_BUCKET="aixcc"
ADMIN_USER=admin
VIEW_USER=readonly

# defaults
echo > /etc/default/chronograf "INFLUXDB_URL=http://localhost:8086"
echo >>/etc/default/chronograf "HOST=localhost"
echo >>/etc/default/chronograf "BASE_PATH=/chronograf"

echo > /etc/default/influxdb2 "INFLUXD_CONFIG_PATH=/etc/influxdb/config.toml"
echo >>/etc/default/influxdb2 "INFLUXD_HTTP_BIND_ADDRESS=127.0.0.1:8086"

# apt
cd /tmp
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list

apt-get update
apt-get install -y jq nginx influxdb2 influxdb2-cli chronograf kapacitor

# influx setup, skip if tokens were already created
if [[ ! -e /etc/influxdb/rw_token ]]; then
    ADMIN_PASS=$(head -c8 /dev/urandom | xxd -ps)
    VIEW_PASS=$(head -c8 /dev/urandom | xxd -ps)

    echo "InfluxDB users:"
    echo "  $ADMIN_USER : $ADMIN_PASS"
    echo "  $VIEW_USER : $VIEW_PASS"
    echo

    systemctl enable chronograf influxdb
    systemctl start chronograf influxdb

    influx setup --org "$INFLUX_ORG" --bucket telegraf --username "$ADMIN_USER" --password "$ADMIN_PASS" --force || true
    influx user create -o "$INFLUX_ORG" -n "$VIEW_USER" -p "$VIEW_PASS" || true
    influx bucket create -n aixcc

    influx auth create --org "$INFLUX_ORG" --read-buckets  --json | jq -r '.token' > /data/influxdb/ro_token
    influx auth create --org "$INFLUX_ORG" --write-buckets --json | jq -r '.token' > /data/influxdb/wo_token
    influx auth create --org "$INFLUX_ORG" --read-buckets --write-buckets --json | jq -r '.token' > /data/influxdb/rw_token
fi

# nginx 
rm -f /etc/nginx/sites-enabled/default # break the symlink
echo >/etc/nginx/sites-enabled/default '
server {
    listen 80;

    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        root /var/www/html;
        try_files $uri /index.html;
    }

    location /chronograf/ {
        proxy_pass http://localhost:8888;
    }
}
'
nginx -t && systemctl reload nginx

# poll-logs service
echo >/etc/systemd/system/poll-logs.service '[Unit]
Description=poll-logs
After=network.target

[Service]
User=tjbecker
Group=tjbecker
WorkingDirectory=/home/tjbecker/aixcc-afc/infra
ExecStart=/bin/bash -c '"'"'PATH="/home/tjbecker/aixcc-afc/.venv/bin:$PATH" ./poll_logs.sh'"'"'

[Install]
WantedBy=multi-user.target'
systemctl enable poll-logs
systemctl start poll-logs

# artifacts cleanup
CRON_CMD="find /var/tmp/data/*/*/*.tar -type f -atime +1 -print0 | sudo xargs -0 rm -f"
CRON_JOB="0 * * * * $CRON_CMD"
(crontab -l 2>/dev/null | grep -Fq "$CRON_CMD") || {
    # If not found, add the cron job
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "Cron job installed."
}
