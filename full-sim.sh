#!/bin/bash -eu

n_build=${n_build:-18}
n_fuzz=${n_fuzz:-6}
use_azure_ai=${use_azure_ai:-0}
model_map=${model_map:-/crs/configs/models-best.toml}

cd "$(dirname "$0")"
basedir=$(pwd)

if [[ $# -lt 2 ]]; then
    echo >&2 "Usage: $0 <round_sim args>"
    exit 1
fi

API_KEY_ID=$(head -c8 /dev/urandom | xxd -ps | tr -d ' \n')
API_KEY_TOKEN=$(head -c8 /dev/urandom | xxd -ps | tr -d ' \n')
SLACK_WEBHOOK=${SLACK_WEBHOOK:-}

cd "$basedir/infra/terraform"
mkdir -p state
statepath=$(pwd)/state/$RANDOM$RANDOM.tfstate
terraform apply -state "$statepath" \
    -parallelism 64 \
    -var api-key-id="$API_KEY_ID" \
    -var api-key-token="$API_KEY_TOKEN" \
    -var fuzz-count="$n_fuzz" \
    -var build-count="$n_build" \
    -var instance-type=Standard_L32as_v3 \
    -var fuzz-instance-type=Standard_D32as_v5 \
    -var region=westus3 \
    -var crs-model-map="$model_map" \
    -var grant-dev-storage=true \
    -var use-azure-ai=$use_azure_ai \
    -auto-approve

resource_group=$(terraform output -state "$statepath" -raw resource_group)
storage_account=$(terraform output -state "$statepath" -raw crs_storage_account)
crs_ip=$(terraform output -state "$statepath" -raw crs_ip)

crs_ssh() {
    "$basedir/infra/terraform/ssh" "$resource_group" "$@"
}

(
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl -X POST --data-urlencode "payload={\"channel\": \"#ai-x-cc\", \"username\": \"round-sim\", \"text\": \"Starting round sim on resource group: ${resource_group}\", \"icon_emoji\": \":umbrella_on_ground:\"}" "${SLACK_WEBHOOK}"
    fi
    sim_args=$(printf "%q " "$@")
    crs_ssh -- screen -dm bash -c '
set -x
cloud-init status --wait </dev/null
r=$?
if [[ $r -ne 0 ]] && [[ $r -ne 2 ]]; then
    exit 1
fi
set -eu

cd /crs && sudo -u crs .venv/bin/python3 round_sim.py --task-server "http://$API_KEY_ID:$API_KEY_TOKEN@localhost:1324" '"$sim_args"' 2>&1 | sudo -u crs tee -a /data/logs/sim.log
sleep 300
sudo systemctl stop crs-task-server crs crs-copy-logs.timer
sudo /crs/infra/backup.sh

curl -X POST --data-urlencode "payload={\"channel\": \"#ai-x-cc\", \"username\": \"round-sim\", \"text\": \"Finished round sim on resource group: ${AZURE_RESOURCE_GROUP}. Data copied to ${dst_url}. Deleting machines in one hour.\", \"icon_emoji\": \":umbrella_on_ground:\"}" "'"${SLACK_WEBHOOK:-}"'" || true
sleep 3600
az login --identity
az group delete -n "$AZURE_RESOURCE_GROUP" --no-wait --yes
'
)
