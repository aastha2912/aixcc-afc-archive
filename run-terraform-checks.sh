#!/usr/bin/env bash

cd "$(dirname "$0")"

set -ex

cd infra/terraform
terraform init
terraform validate
terraform plan -state check.tfstate