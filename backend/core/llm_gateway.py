"""
4-layer LLM gateway.
Layer 1: Claude Sonnet (primary)
Layer 2: Grok via Groq API (fallback)
Layer 3: Offline template (last resort — no external calls)

Used by ticket_resolver and self_healer agents.
"""
import logging
from typing import Optional
from core.config import settings

logger = logging.getLogger(__name__)


class LLMGateway:
    """Routes LLM calls through a priority chain with automatic fallback."""

    async def complete(
        self,
        prompt: str,
        system: str = "You are ResilientAI, an expert IT support and security agent.",
        max_tokens: int = 1024,
    ) -> dict:
        """
        Attempt completion through each layer in order.
        Returns: {"text": str, "model": str, "layer": int}
        """
        # ── Layer 1: Claude Sonnet ─────────────────────────
        if settings.ANTHROPIC_API_KEY:
            try:
                result = await self._claude(prompt, system, max_tokens)
                return {**result, "layer": 1}
            except Exception as e:
                logger.warning(f"[LLM] Layer 1 (Claude) failed: {e}")

        # ── Layer 2: Grok via Groq ─────────────────────────
        if settings.GROQ_API_KEY:
            try:
                result = await self._grok(prompt, system, max_tokens)
                return {**result, "layer": 2}
            except Exception as e:
                logger.warning(f"[LLM] Layer 2 (Grok) failed: {e}")

        # ── Layer 3: Offline template ──────────────────────
        logger.warning("[LLM] All AI layers failed — using offline template")
        return await self._offline(prompt)

    async def _claude(self, prompt: str, system: str, max_tokens: int) -> dict:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        message = await client.messages.create(
            model=settings.LLM_PRIMARY,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "text": message.content[0].text,
            "model": settings.LLM_PRIMARY,
        }

    async def _grok(self, prompt: str, system: str, max_tokens: int) -> dict:
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                json={
                    "model": settings.LLM_FALLBACK,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                },
            )
            r.raise_for_status()
            data = r.json()
            return {
                "text": data["choices"][0]["message"]["content"],
                "model": settings.LLM_FALLBACK,
            }

    async def _offline(self, prompt: str) -> dict:
        """
        Deterministic offline response — used when all AI layers are down.
        Provides a safe, human-readable acknowledgement.
        """
        text = (
            "Your request has been received and logged. "
            "Our AI systems are temporarily unavailable. "
            "A human agent will review this ticket within 2 business hours. "
            "Ticket reference: [auto-assigned on save]"
        )
        return {"text": text, "model": "offline-template", "layer": 3}


# Singleton — import this everywhere
llm = LLMGateway()
