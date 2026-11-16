#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
binary="../work/prometheus-demo/prometheus-3.16.0.darwin-arm64/prometheus"
if [[ ! -x "$binary" ]]; then
  echo "Official Prometheus binary missing. See demo/prometheus/README.md." >&2
  exit 1
fi
exec "$binary" --config.file=demo/prometheus/prometheus.yml --storage.tsdb.path=../work/prometheus-demo/tsdb --storage.tsdb.retention.time=24h --web.listen-address=127.0.0.1:9090
