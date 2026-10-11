"""Tenant-scoped retrieval from integrity-checked, published knowledge articles."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.knowledge_article import KnowledgeArticle


_TOKEN_RE = re.compile(r"[\w-]{2,}", re.UNICODE)
_MAX_CANDIDATES = 500
_MAX_EXCERPT_CHARS = 4000


class KnowledgeIntegrityError(RuntimeError):
    """A published article's stored content does not match its recorded digest."""


def _safe_source_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return value


def _tokens(value: str) -> set[str]:
    return {token.casefold() for token in _TOKEN_RE.findall(value or "")}


async def retrieve_knowledge_articles(
    db: AsyncSession,
    *,
    tenant_id: str,
    query: str,
    category: str | None = None,
    limit: int = 3,
) -> list[dict]:
    """Return only published global or same-tenant articles, ranked lexically.

    Retrieval is deliberately deterministic and dependency-free. Article content is
    reference material, not instructions; callers must place it in an untrusted-data
    section of the model prompt. A content hash mismatch fails closed.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("A verified tenant_id is required for knowledge retrieval.")
    if not isinstance(query, str) or not query.strip():
        return []
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError("limit must be an integer between 1 and 10.")

    statement = select(KnowledgeArticle).where(
        KnowledgeArticle.status == "published",
        or_(
            KnowledgeArticle.org_id == tenant_id,
            KnowledgeArticle.org_id.is_(None),
        ),
    )
    if category:
        statement = statement.where(
            KnowledgeArticle.category.in_([category, "general"])
        )
    statement = statement.order_by(
        KnowledgeArticle.updated_at.desc(), KnowledgeArticle.id.asc()
    ).limit(_MAX_CANDIDATES)
    rows = list((await db.scalars(statement)).all())

    query_tokens = _tokens(query)
    ranked: list[tuple[float, KnowledgeArticle]] = []
    for article in rows:
        actual_digest = hashlib.sha256(article.content.encode("utf-8")).hexdigest()
        if not hashlib.compare_digest(actual_digest, article.content_sha256.lower()):
            raise KnowledgeIntegrityError(
                f"Published knowledge article integrity check failed for id={article.id}."
            )
        title_tokens = _tokens(article.title)
        content_tokens = _tokens(article.content)
        score = float(len(query_tokens & content_tokens))
        score += 2.0 * len(query_tokens & title_tokens)
        if category and article.category == category:
            score += 2.0
        if score > 0:
            ranked.append((score, article))

    ranked.sort(key=lambda item: (-item[0], item[1].id))
    result = []
    for score, article in ranked[:limit]:
        result.append({
            "article_id": article.id,
            "slug": article.slug,
            "version": article.version,
            "title": article.title,
            "category": article.category,
            "content": article.content[:_MAX_EXCERPT_CHARS],
            "content_sha256": article.content_sha256,
            "source_url": _safe_source_url(article.source_url),
            "score": round(score, 3),
            "scope": "global" if article.org_id is None else "tenant",
        })
    return result
