# Local synthetic Prometheus demo

Real Prometheus 3.16.0 scrapes a clearly synthetic exporter at 127.0.0.1:9108 every two seconds. Prometheus binds only to 127.0.0.1:9090. This does not measure or verify production recovery.

The separate ignored `.env.telemetry` configures the existing read-only adapter. `.env` and API credentials are untouched. `PROMETHEUS_DEMO=1` forces production verification status to `NOT_VERIFIED`, even when `demo_checks_passed=true`. Do not turn this flag off while querying synthetic metrics. Provider details expose this scope; the header says DEMO.

Run from the repository in separate terminals:

```bash
.venv/bin/python -m scripts.demo_metrics
./scripts/run_demo_prometheus.sh
./run.sh serve
```

Change synthetic signals, then allow at least one two-second scrape interval:

```bash
.venv/bin/python -m scripts.demo_metrics --state degraded
.venv/bin/python -m scripts.demo_metrics --state down
.venv/bin/python -m scripts.demo_metrics --state healthy
```

In IncidentIQ use Check connections to query current telemetry, or submit an incident through the existing reviewed workflow. The adapter checks service availability >=1, error-rate <=0.01 and pool usage <=0.8. Healthy values are 1, 0.002 and 0.35. Degraded values are 1, 0.12 and 0.95. These are authored demo values, not measured production values. No Groq or Hindsight calls are required to run the exporter or query Prometheus directly.

Prometheus API/UI: http://127.0.0.1:9090. Exporter: http://127.0.0.1:9108/metrics. Stop each process with Ctrl+C. No launch agent or public deployment was installed. Local TSDB retention is 24 hours.

Official Darwin arm64 binary, installed outside Git under `../work/prometheus-demo/`:
https://github.com/prometheus/prometheus/releases/download/v3.16.0/prometheus-3.16.0.darwin-arm64.tar.gz

Verified published SHA256:
`f7c71b553316f822bdd860a3ea527ebefb2f8e944e5b7dfd419ae2653cf3ba01`

On another platform download the corresponding official archive, verify its published checksum and adjust the helper binary path. The original MIT license and application architecture are preserved.
