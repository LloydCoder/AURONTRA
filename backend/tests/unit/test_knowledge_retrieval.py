"""Security and isolation tests for knowledge retrieval."""
import hashlib
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from core.database import AsyncSessionLocal
from models.knowledge_article import KnowledgeArticle
from models.organization import Organization
from knowledge.retrieval import KnowledgeIntegrityError, retrieve_knowledge_articles


def _article(*, article_id, org_id, title, content, status="published", source_url=None, approved=True):
    return KnowledgeArticle(
        id=article_id,
        org_id=org_id,
        article_key=f"{org_id or 'global'}:{article_id}:v1",
        slug=article_id,
        title=title,
        category="connectivity",
        content=content,
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        status=status,
        version=1,
        source_url=source_url,
        approved_by="knowledge-admin" if status == "published" and approved else None,
        approved_at=datetime.now(timezone.utc) if status == "published" and approved else None,
    )


@pytest.mark.asyncio
async def test_retrieval_returns_only_published_global_and_current_tenant_articles():
    async with AsyncSessionLocal() as db:
        db.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        await db.commit()
        db.add_all([
            _article(article_id="own-vpn", org_id="test-tenant", title="VPN troubleshooting", content="Reconnect to the approved VPN client."),
            _article(article_id="global-vpn", org_id=None, title="VPN basics", content="Check network access and reconnect."),
            _article(article_id="other-vpn", org_id="other-tenant", title="VPN secret", content="Tenant-private VPN details."),
            _article(article_id="draft-vpn", org_id="test-tenant", title="Draft VPN", content="Unapproved steps.", status="draft"),
        ])
        await db.commit()
        results = await retrieve_knowledge_articles(
            db, tenant_id="test-tenant", query="VPN reconnect", category="connectivity"
        )
    ids = {item["article_id"] for item in results}
    assert "own-vpn" in ids
    assert "global-vpn" in ids
    assert "other-vpn" not in ids
    assert "draft-vpn" not in ids


@pytest.mark.asyncio
async def test_retrieval_fails_closed_on_published_article_digest_mismatch():
    async with AsyncSessionLocal() as db:
        db.add(_article(
            article_id="tampered-vpn",
            org_id="test-tenant",
            title="VPN troubleshooting",
            content="Original approved content.",
        ))
        await db.commit()
        article = await db.get(KnowledgeArticle, "tampered-vpn")
        article.content = "Modified after approval."
        await db.commit()
        with pytest.raises(KnowledgeIntegrityError):
            await retrieve_knowledge_articles(
                db, tenant_id="test-tenant", query="VPN", category="connectivity"
            )


@pytest.mark.asyncio
async def test_retrieval_requires_verified_tenant_and_bounded_limit():
    async with AsyncSessionLocal() as db:
        with pytest.raises(ValueError):
            await retrieve_knowledge_articles(db, tenant_id="", query="VPN")
        with pytest.raises(ValueError):
            await retrieve_knowledge_articles(db, tenant_id="test-tenant", query="VPN", limit=11)


@pytest.mark.asyncio
async def test_retrieval_does_not_return_plaintext_http_source_urls():
    async with AsyncSessionLocal() as db:
        db.add(_article(
            article_id="unsafe-url",
            org_id="test-tenant",
            title="VPN troubleshooting",
            content="Reconnect to VPN.",
            source_url="http://internal.example.invalid/article",
        ))
        await db.commit()
        results = await retrieve_knowledge_articles(
            db, tenant_id="test-tenant", query="VPN", category="connectivity"
        )
    assert results[0]["source_url"] is None


@pytest.mark.asyncio
async def test_database_rejects_published_article_without_approval_metadata():
    async with AsyncSessionLocal() as db:
        db.add(_article(
            article_id="unapproved-vpn",
            org_id="test-tenant",
            title="Unapproved VPN",
            content="Unreviewed steps.",
            approved=False,
        ))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.asyncio
async def test_database_rejects_oversized_knowledge_article_content():
    oversized = "x" * 100001
    async with AsyncSessionLocal() as db:
        db.add(_article(
            article_id="oversized-vpn",
            org_id="test-tenant",
            title="Oversized VPN",
            content=oversized,
        ))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()
