"""IOC Pingback: watches, sightings, and SOC-to-SOC contacts

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-07

PING  = anonymous sighting alert — watcher is notified, seeker identity never revealed.
CONTACT = SOC-to-SOC introduction request — watcher receives a contact request and may
          accept (revealing both parties) or decline.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A user places a watch on an IOC value
    op.create_table(
        "ioc_watches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_kind", sa.String(50), nullable=False),   # ip_address, domain, hash, url, cve, ...
        sa.Column("ioc_value_hash", sa.String(64), nullable=False),  # sha256(normalised lower value)
        sa.Column("ioc_value_display", sa.String(512), nullable=False),  # shown in UI / notifications
        sa.Column(
            "mode",
            sa.String(10),
            nullable=False,
            server_default="ping",
        ),  # 'ping' | 'contact'
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        # Contact-mode delivery preferences
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("contact_note", sa.Text, nullable=True),   # shown to seeker if watcher accepts
        sa.Column("notify_inbox", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("notify_email", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("notify_webhook", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "ioc_value_hash", "mode", name="uq_ioc_watch_user_ioc_mode"),
    )
    op.create_index("ix_ioc_watches_value_hash", "ioc_watches", ["ioc_value_hash"])
    op.create_index("ix_ioc_watches_user_id", "ioc_watches", ["user_id"])
    op.create_index("ix_ioc_watches_tenant_id", "ioc_watches", ["tenant_id"])
    # Fast lookup when any IOC is hit
    op.create_index("ix_ioc_watches_active_hash", "ioc_watches", ["active", "ioc_value_hash"])

    # Recorded when a different user/tenant hits a watched IOC
    op.create_table(
        "ioc_sightings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("watch_id", UUID(as_uuid=True), sa.ForeignKey("ioc_watches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_value_hash", sa.String(64), nullable=False),
        # Sighting context — what triggered it (enrichment, search, ingest)
        sa.Column("trigger", sa.String(50), nullable=False, server_default="enrichment"),
        # Anonymous: seeker_tenant_id stored but NOT surfaced to watcher for PING mode
        sa.Column("seeker_tenant_id", UUID(as_uuid=True), nullable=True),
        # For CONTACT mode, seeker may optionally attach a message
        sa.Column("seeker_message", sa.Text, nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("delivered", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ioc_sightings_watch_id", "ioc_sightings", ["watch_id"])
    op.create_index("ix_ioc_sightings_delivered", "ioc_sightings", ["delivered"])

    # SOC-to-SOC contact thread — created when a seeker requests contact
    # Only created for mode='contact' watches. Watcher accepts/declines.
    op.create_table(
        "ioc_contacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("sighting_id", UUID(as_uuid=True), sa.ForeignKey("ioc_sightings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("watch_id", UUID(as_uuid=True), sa.ForeignKey("ioc_watches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_value_hash", sa.String(64), nullable=False),
        # seeker = who saw the IOC and wants to connect
        sa.Column("seeker_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("seeker_tenant_id", UUID(as_uuid=True), nullable=True),
        # watcher = who placed the watch
        sa.Column("watcher_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("seeker_message", sa.Text, nullable=True),
        sa.Column("watcher_response", sa.Text, nullable=True),
        # pending | accepted | declined
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        # Only after acceptance: both parties see contact details
        sa.Column("seeker_revealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("watcher_revealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ioc_contacts_watch_id", "ioc_contacts", ["watch_id"])
    op.create_index("ix_ioc_contacts_watcher_user_id", "ioc_contacts", ["watcher_user_id"])
    op.create_index("ix_ioc_contacts_seeker_user_id", "ioc_contacts", ["seeker_user_id"])
    op.create_index("ix_ioc_contacts_status", "ioc_contacts", ["status"])

    # Inbox items: generic notification store for both PING and CONTACT events
    op.create_table(
        "inbox_items",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),  # 'ping' | 'contact_request' | 'contact_accepted' | 'digest'
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("metadata", JSONB, nullable=True),  # watch_id, contact_id, ioc_value_hash etc — no PII
        sa.Column("read", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_inbox_items_user_id", "inbox_items", ["user_id"])
    op.create_index("ix_inbox_items_unread", "inbox_items", ["user_id", "read"])


def downgrade() -> None:
    op.drop_index("ix_inbox_items_unread", "inbox_items")
    op.drop_index("ix_inbox_items_user_id", "inbox_items")
    op.drop_table("inbox_items")
    op.drop_index("ix_ioc_contacts_status", "ioc_contacts")
    op.drop_index("ix_ioc_contacts_seeker_user_id", "ioc_contacts")
    op.drop_index("ix_ioc_contacts_watcher_user_id", "ioc_contacts")
    op.drop_index("ix_ioc_contacts_watch_id", "ioc_contacts")
    op.drop_table("ioc_contacts")
    op.drop_index("ix_ioc_sightings_delivered", "ioc_sightings")
    op.drop_index("ix_ioc_sightings_watch_id", "ioc_sightings")
    op.drop_table("ioc_sightings")
    op.drop_index("ix_ioc_watches_active_hash", "ioc_watches")
    op.drop_index("ix_ioc_watches_tenant_id", "ioc_watches")
    op.drop_index("ix_ioc_watches_user_id", "ioc_watches")
    op.drop_index("ix_ioc_watches_value_hash", "ioc_watches")
    op.drop_table("ioc_watches")
