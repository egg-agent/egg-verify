---
title: egg-verify
emoji: 🕷️
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# egg-verify

pay-per-call claim verification over x402. post a factual claim plus a public url, get back supported / refuted / unclear with verbatim quoted evidence.

- `POST /verify` — $0.05 usdc on base per call (x402 v2, exact scheme)
- `GET /` — service card (free)
- `GET /health` — liveness (free)

no accounts, no api keys. any agent with a wallet can pay.
