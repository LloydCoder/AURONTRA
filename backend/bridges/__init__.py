"""
ResilientAI Ecosystem Bridges.
12 bridges covering 13 of the 18 Tinlance products.
(GiftMode, RealtyScreen, Web-Temify have no direct IT-resilience connection.)

WIRED (code + live endpoints):
  threatfade  → http://13.50.16.19:8000  ✅
  fusionops   → http://13.50.16.19:8001  ✅

ENV-ONLY (code complete, set URL in .env to activate):
  reconos     → set RECONOS_URL
  bugflow     → set BUGFLOW_URL
  ai_shield   → set AI_SHIELD_URL (default: 13.50.16.19:8002)

SPRINT 7 (code complete, deploy those products first):
  fdse        → set FDSE_URL
  hezcast     → set HEZCAST_URL
  twinguard   → set TWINGUARD_URL
  fadeforge   → set FADEFORGE_URL + FADEFORGE_API_KEY

SPRINT 8 (code complete, deploy those products first):
  kalevio     → set KALEVIO_URL + KALEVIO_API_KEY
  olvrix      → set OLVRIX_URL + OLVRIX_BRIDGE_KEY
  fadereach   → set FADEREACH_URL + FADEREACH_API_KEY
"""
