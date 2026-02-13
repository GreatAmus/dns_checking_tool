#!/usr/bin/env bash
set -euo pipefail

fly deploy -c fly/resolver/fly.toml -a dns-checking-resolver
fly deploy -c fly/api/fly.toml -a dns-settings-checker
