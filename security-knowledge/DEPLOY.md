# Deployment Guide: z.je Security Knowledge Platform

## Prerequisites
- SSH key at `~/.ssh/ZOIDBERG` for z@z.je
- Python 3.11+ with venv
- PostgreSQL 16 with pgvector extension
- Redis 7+
- Docker (optional, for Tor)

## Quick Deploy Steps

### 1. SSH to z.je
```bash
ssh -i ~/.ssh/ZOIDBERG z@z.je
```

### 2. Pull Latest Code
```bash
cd /home/z/z-zoidberg/security-knowledge
git pull origin main
```

### 3. Install Dependencies
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
pip install httpx[socks]  # Tor proxy support
```

### 4. Run Database Migration
```bash
alembic upgrade head
```

### 5. Seed Knowledge (first time or update)
```bash
python -m scripts.seed_knowledge
python -m scripts.dedup_entities
```

### 6. Update .env
```bash
# Add these new variables to .env:
RecordedFutureAPI=          # Your Recorded Future API key
FEED_POLL_USER_AGENT=Zoidberg/1.0 (Security Knowledge Platform; https://z.je)
FEED_POLL_INTERVAL_SECONDS=1200
TOR_SCRAPE_ENABLED=false    # Set true when Tor is running
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
AI_ENRICHMENT_PROVIDER=     # "openai" or "anthropic"
AI_ENRICHMENT_MODEL=gpt-4o-mini
```

### 7. Restart Services
```bash
# Using systemd (if configured)
sudo systemctl restart sk-api sk-worker

# OR using docker-compose
docker-compose up -d --build

# OR manually
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
python -m arq app.worker.WorkerSettings &
```

### 8. Verify
```bash
curl http://localhost:8000/health
# Should return {"status":"ok"}

# Check new endpoints
curl http://localhost:8000/api/v1/ticker/trends -H "Authorization: Bearer <token>"
curl http://localhost:8000/api/v1/admin/settings/user-agent -H "Authorization: Bearer <token>"
```

## Database Dump & Restore

### Create Dump
```bash
cd /home/z/z-zoidberg/security-knowledge
./scripts/dump_db.sh  # Creates dumps/sk_portable.dump.bz2
```

### Restore Dump (remote)
```bash
scp dumps/sk_portable.dump.bz2 z.je:/home/z/z-zoidberg/security-knowledge/dumps/
ssh z.je 'cd /home/z/z-zoidberg/security-knowledge && ./scripts/upgrade.sh'
```

## Tor Scraping Setup (Optional)

```bash
# Start Tor proxy
docker run -d --name tor -p 9050:9050 dperson/torproxy

# Enable in .env
TOR_SCRAPE_ENABLED=true

# Restart worker
sudo systemctl restart sk-worker
```

## QA Checklist

- [ ] `/health` returns 200
- [ ] `/api/v1/entities/` returns 401 without auth, 200 with auth
- [ ] `/api/v1/ticker/trends` returns data
- [ ] `/api/v1/ticker/news` returns data
- [ ] `/api/v1/ticker/breaches` returns data
- [ ] `/api/v1/ticker/flag` creates a flagged item
- [ ] `/api/v1/ticker/flags` lists flagged items
- [ ] `/api/v1/ticker/flag/{id}/ack` ACKs an item
- [ ] `/api/v1/admin/settings/user-agent` GET/POST
- [ ] Feed poller running on 20min cycle
- [ ] Recorded Future enrichment works (if key set)
- [ ] UI: https://z.je/ loads with ticker boxes
- [ ] UI: https://z.je/ search box works
- [ ] UI: https://z.je/ flagged items tab switching works
