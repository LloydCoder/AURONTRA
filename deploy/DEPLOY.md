# ResilientAI — Deployment Runbook
**Server:** AWS EC2 Stockholm `13.50.16.19` (eu-north-1)
**Port:** 8003
**Neighbours:** ThreatFade:8000 | FusionOps:8080 | AI Shield:8002

---

## Pre-flight Checklist (do these before SSH)

- [ ] GitHub repo `github.com/Tinlance/resilientai` has all code pushed
- [ ] `.env` file ready (copy from `.env.example`, fill in keys)
- [ ] `EC2_SSH_KEY` secret added to GitHub repo → Settings → Secrets
- [ ] LemonSqueezy variant IDs filled in (store 247127)
- [ ] Anthropic API key available

---

## Step 1 — SSH into EC2

```bash
ssh -i ~/.ssh/tinlance-ec2.pem ubuntu@13.50.16.19
```

---

## Step 2 — First-time setup (run once)

```bash
# Clone the repo
sudo mkdir -p /opt/tinlance
sudo chown ubuntu:ubuntu /opt/tinlance
git clone https://github.com/Tinlance/resilientai.git /opt/tinlance/resilientai
cd /opt/tinlance/resilientai

# Create .env
cp .env.example .env
nano .env   # Fill in ANTHROPIC_API_KEY, LEMONSQUEEZY keys, CLERK keys
            # Leave bridge URLs empty for now — they activate when you set them

# Run the deploy script
chmod +x deploy/setup_ec2.sh
./deploy/setup_ec2.sh
```

---

## Step 3 — Verify deployment

```bash
# Service status
sudo systemctl status resilientai

# Live logs
sudo journalctl -u resilientai -f

# Health check (should return {"status":"ok"})
curl http://localhost:8003/health/ | python3 -m json.tool

# Bridge status (shows all 12 ecosystem bridges)
curl http://localhost:8003/health/bridges | python3 -m json.tool

# API docs
curl http://13.50.16.19/resilientai/docs
```

---

## Step 4 — Set up SSL

```bash
sudo certbot --nginx -d api.resilientai.tinlance.com
# Follow the prompts — certbot auto-configures Nginx
```

---

## Step 5 — Activate ecosystem bridges (`.env` only)

```bash
nano /opt/tinlance/resilientai/.env

# Add these as products deploy:
AI_SHIELD_URL=http://127.0.0.1:8002    # Already on same EC2
RECONOS_URL=http://127.0.0.1:XXXX      # When ReconOS deploys here
BUGFLOW_URL=http://127.0.0.1:XXXX      # When BugFlow deploys here

# Restart to pick up new env vars
sudo systemctl restart resilientai
```

---

## Step 6 — Activate Olvrix Widgets bridge (other side)

On the Olvrix Widgets server, add to its `.env`:

```bash
RESILIENTAI_API_URL=http://13.50.16.19:8003
RESILIENTAI_API_KEY=ra_<get from POST /onboarding/register>
```

Generate the API key:
```bash
curl -X POST http://localhost:8003/onboarding/register \
  -H "Content-Type: application/json" \
  -d '{"org_name":"Tinlance Internal","admin_email":"nwachukwuchinaemerem8@gmail.com","plan":"business","device_count":10}'
# Copy the api_key from the response
```

---

## Useful commands

```bash
# Restart service
sudo systemctl restart resilientai

# Stop service
sudo systemctl stop resilientai

# Check what's running on all Tinlance ports
ss -tlnp | grep -E "8000|8002|8003|8080"

# View all Tinlance services
sudo systemctl list-units | grep tinlance

# Tail logs for all 3 services at once
sudo journalctl -u threatfade -u fusionops -u resilientai -f

# Update and redeploy manually
cd /opt/tinlance/resilientai && git pull && sudo systemctl restart resilientai
```

---

## Port map — EC2 Stockholm 13.50.16.19

| Port | Service | Status |
|------|---------|--------|
| 80   | Nginx (reverse proxy) | ✅ Live |
| 443  | Nginx SSL | After certbot |
| 8000 | ThreatFade v0.2.0 | ✅ Live |
| 8002 | AI Shield | ✅ Live |
| 8003 | **ResilientAI** | After deploy |
| 8010 | Olvrix Widgets | Pending |
| 8080 | FusionOps API | ✅ Live |

---

## Auto-deploy after this (GitHub Actions)

Every push to `main`:
1. Runs 236 tests
2. If all pass → SSH into EC2 → `git pull` → `pip install` → `systemctl restart`
3. Runs health check → fails the deploy if `{"status":"ok"}` not returned

**Required:** Add `EC2_SSH_KEY` to GitHub repo secrets:
- Settings → Secrets and variables → Actions → New repository secret
- Name: `EC2_SSH_KEY`
- Value: contents of `~/.ssh/tinlance-ec2.pem`
