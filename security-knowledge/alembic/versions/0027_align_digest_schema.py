"""Align digest tables with ORM models.

Revision ID: 0027
Revises: 0026
Create Date: 2026-05-09
"""
from alembic import op


revision = "0027"
down_revision = "0026_entity_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # digest_subscriptions: old schema (saved_search/channel/config) -> model schema
    op.execute("ALTER TABLE digest_subscriptions ALTER COLUMN saved_search_id DROP NOT NULL")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS name varchar(255)")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS schedule varchar(100) NOT NULL DEFAULT '0 8 * * *'")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS frequency varchar(50) NOT NULL DEFAULT 'daily'")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS channels jsonb NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS filters jsonb NOT NULL DEFAULT '{}'::jsonb")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS template text NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS next_run_at timestamptz")
    op.execute("ALTER TABLE digest_subscriptions ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()")

    op.execute(
        """
        UPDATE digest_subscriptions
        SET name = COALESCE(NULLIF(config->>'name', ''), 'Digest ' || left(id::text, 8))
        WHERE name IS NULL
        """
    )
    op.execute(
        """
        UPDATE digest_subscriptions
        SET frequency = COALESCE(NULLIF(config->>'frequency', ''), frequency, 'daily')
        """
    )
    op.execute(
        """
        UPDATE digest_subscriptions
        SET channels = CASE
            WHEN jsonb_typeof(channels) = 'array' THEN channels
            WHEN channel IS NOT NULL AND channel <> '' THEN jsonb_build_array(channel)
            ELSE '[]'::jsonb
        END
        """
    )
    op.execute(
        """
        UPDATE digest_subscriptions
        SET filters = CASE
            WHEN jsonb_typeof(filters) = 'object' THEN filters
            WHEN jsonb_typeof(config) = 'object' THEN config
            ELSE '{}'::jsonb
        END
        """
    )
    op.execute("ALTER TABLE digest_subscriptions ALTER COLUMN name SET NOT NULL")

    # digest_runs: old schema -> model schema
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS subscription_id uuid")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS tenant_id uuid")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS item_count integer NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS items_count integer NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS error text")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS content text NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now()")
    op.execute("ALTER TABLE digest_runs ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()")
    op.execute(
        """
        UPDATE digest_runs dr
        SET subscription_id = ds.id
        FROM digest_subscriptions ds
        WHERE dr.subscription_id IS NULL
          AND dr.saved_search_id = ds.saved_search_id
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS updated_at")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS created_at")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS content")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS error")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS items_count")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS item_count")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS tenant_id")
    op.execute("ALTER TABLE digest_runs DROP COLUMN IF EXISTS subscription_id")

    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS updated_at")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS next_run_at")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS template")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS filters")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS channels")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS frequency")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS schedule")
    op.execute("ALTER TABLE digest_subscriptions DROP COLUMN IF EXISTS name")
    op.execute("ALTER TABLE digest_subscriptions ALTER COLUMN saved_search_id SET NOT NULL")
