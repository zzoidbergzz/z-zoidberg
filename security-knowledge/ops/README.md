# ops/

systemd units, dashboards, alert rules, and the Apache reverse-proxy
config for the Security Knowledge stack.

## Units

- `security-knowledge.service` — uvicorn FastAPI app on `127.0.0.1:8010`.
- `security-knowledge-worker.service` — ARQ worker that runs ingestion
  jobs, enrichment jobs, and the cron-driven feed poller.

The worker unit is **not installed by default**.  When you are ready to
turn on background ingestion, install it like this:

```bash
sudo cp ops/security-knowledge-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now security-knowledge-worker.service
sudo systemctl status security-knowledge-worker.service
```

`journalctl -u security-knowledge-worker -f` for live logs.

## Other artifacts

- `grafana_dashboard.json` — pre-built dashboard for the Prometheus
  metrics exposed by the FastAPI app.
- `prometheus_alerts.yaml` — alert rules (4xx spike, queue backlog,
  enrichment budget exhausted, etc.).
- `zje-sk-proxy.conf` — Apache vhost snippet that fronts the uvicorn
  socket at https://z.je.
