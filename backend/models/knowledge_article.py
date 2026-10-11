"""Versioned, tenant-scoped knowledge article model."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String,
    Text, UniqueConstraint, func,
)
from core.database import Base


class KnowledgeArticle(Base):
    __tablename__ = "knowledge_articles"
    __table_args__ = (
        CheckConstraint("status IN ('draft', 'published', 'archived')", name="ck_knowledge_article_status"),
        CheckConstraint("version >= 1", name="ck_knowledge_article_version"),
        CheckConstraint("length(content_sha256) = 64", name="ck_knowledge_article_content_hash_length"),
        UniqueConstraint("org_id", "slug", "version", name="uq_knowledge_article_tenant_slug_version"),
        Index("ix_knowledge_articles_tenant_status", "org_id", "status"),
        Index("ix_knowledge_articles_category_status", "category", "status"),
    )

    id = Column(String(36), primary_key=True)
    # NULL org_id is reserved for globally approved, read-only articles.
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True)
    article_key = Column(String(400), nullable=False, unique=True)
    slug = Column(String(160), nullable=False)
    title = Column(String(300), nullable=False)
    category = Column(String(64), nullable=False, default="general")
    content = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="draft")
    version = Column(Integer, nullable=False, default=1)
    source_url = Column(String(2048), nullable=True)
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    def __init__(self, **kwargs):
        kwargs.setdefault("status", "draft")
        kwargs.setdefault("version", 1)
        kwargs.setdefault("category", "general")
        super().__init__(**kwargs)
