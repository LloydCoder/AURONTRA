"""AI suggestion provenance and tenant-scoped approved knowledge articles."""
from alembic import op
import sqlalchemy as sa

revision = "0008_ticket_ai_knowledge"
down_revision = "0007_telemetry_evidence"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "tickets" in tables:
        columns = {column["name"] for column in inspector.get_columns("tickets")}
        additions = [
            ("ai_prompt_version", sa.String(length=64)),
            ("ai_prompt_sha256", sa.String(length=64)),
            ("ai_response_sha256", sa.String(length=64)),
            ("ai_knowledge_refs", sa.JSON()),
            ("ai_generated_at", sa.DateTime(timezone=True)),
        ]
        for name, column_type in additions:
            if name not in columns:
                op.add_column("tickets", sa.Column(name, column_type, nullable=True))

    if "knowledge_articles" not in tables:
        op.create_table(
            "knowledge_articles",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("org_id", sa.String(length=64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True),
            sa.Column("article_key", sa.String(length=400), nullable=False, unique=True),
            sa.Column("slug", sa.String(length=160), nullable=False),
            sa.Column("title", sa.String(length=300), nullable=False),
            sa.Column("category", sa.String(length=64), nullable=False, server_default="general"),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("content_sha256", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="draft"),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("source_url", sa.String(length=2048), nullable=True),
            sa.Column("approved_by", sa.String(length=128), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint("status IN ('draft', 'published', 'archived')", name="ck_knowledge_article_status"),
            sa.CheckConstraint("status != 'published' OR (approved_by IS NOT NULL AND length(trim(approved_by)) > 0 AND approved_at IS NOT NULL)", name="ck_knowledge_article_published_approval"),
            sa.CheckConstraint("version >= 1", name="ck_knowledge_article_version"),
            sa.CheckConstraint("length(content_sha256) = 64", name="ck_knowledge_article_content_hash_length"),
            sa.UniqueConstraint("org_id", "slug", "version", name="uq_knowledge_article_tenant_slug_version"),
        )
        op.create_index(
            "ix_knowledge_articles_tenant_status", "knowledge_articles", ["org_id", "status"]
        )
        op.create_index(
            "ix_knowledge_articles_category_status", "knowledge_articles", ["category", "status"]
        )

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE knowledge_articles ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE knowledge_articles FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY knowledge_articles_read ON knowledge_articles FOR SELECT USING ("
            "NULLIF(current_setting('app.current_org_id', true), '') IS NOT NULL "
            "AND ((status = 'published' AND approved_by IS NOT NULL AND approved_at IS NOT NULL "
            "AND (org_id = NULLIF(current_setting('app.current_org_id', true), '') OR org_id IS NULL)) "
            "OR (org_id = NULLIF(current_setting('app.current_org_id', true), '') "
            "AND status = 'draft' AND approved_by IS NULL AND approved_at IS NULL)))"
        )
        op.execute(
            "CREATE POLICY knowledge_articles_insert ON knowledge_articles FOR INSERT "
            "WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '') AND status = 'draft' AND approved_by IS NULL AND approved_at IS NULL)"
        )
        op.execute(
            "CREATE POLICY knowledge_articles_update ON knowledge_articles FOR UPDATE "
            "USING (org_id = NULLIF(current_setting('app.current_org_id', true), '') AND status = 'draft') "
            "WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '') AND status = 'draft' AND approved_by IS NULL AND approved_at IS NULL)"
        )
        op.execute(
            "CREATE POLICY knowledge_articles_delete ON knowledge_articles FOR DELETE "
            "USING (org_id = NULLIF(current_setting('app.current_org_id', true), '') AND status = 'draft')"
        )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS knowledge_articles_delete ON knowledge_articles")
        op.execute("DROP POLICY IF EXISTS knowledge_articles_update ON knowledge_articles")
        op.execute("DROP POLICY IF EXISTS knowledge_articles_insert ON knowledge_articles")
        op.execute("DROP POLICY IF EXISTS knowledge_articles_read ON knowledge_articles")
    inspector = sa.inspect(bind)
    if "knowledge_articles" in set(inspector.get_table_names()):
        op.drop_table("knowledge_articles")
    if "tickets" in set(inspector.get_table_names()):
        columns = {column["name"] for column in inspector.get_columns("tickets")}
        for name in ("ai_generated_at", "ai_knowledge_refs", "ai_response_sha256", "ai_prompt_sha256", "ai_prompt_version"):
            if name in columns:
                op.drop_column("tickets", name)
