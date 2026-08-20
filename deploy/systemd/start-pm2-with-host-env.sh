#!/usr/bin/env bash

set -euo pipefail

pm2=/home/admin/.nvm/versions/node/v24.16.0/lib/node_modules/botmux/node_modules/.bin/pm2

# PM2 resurrect restores the saved application list, including its old env
# snapshot. Refresh every process from systemd's host-only EnvironmentFile so a
# reboot cannot silently disable the result-publish bridge.
"${pm2}" resurrect
"${pm2}" reload all --update-env
