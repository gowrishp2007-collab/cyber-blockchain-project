from datetime import datetime
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

ENV_FILE = Path(__file__).resolve().parent / ".env"

load_dotenv(ENV_FILE)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./cyber_threats.db"
)

# Supabase Transaction Pooler:
# If the URL uses the plain "postgres" username,
# convert it to the project-specific pooler username.
if (
    "pooler.supabase.com" in DATABASE_URL
    and DATABASE_URL.startswith("postgresql")
):
    DATABASE_URL = DATABASE_URL.replace(
        "://postgres:",
        "://postgres.rfbmuteinautlzzswmqy:",
        1
    )


# ============================================================
# DATABASE ENGINE
# ============================================================

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={
            "check_same_thread": False
        },
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )


# ============================================================
# SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ============================================================
# BASE
# ============================================================

Base = declarative_base()


# ============================================================
# THREAT TABLE
# ============================================================

class Threat(Base):
    __tablename__ = "threats"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    threat_type = Column(
        String,
        nullable=False
    )

    threat_value = Column(
        String,
        nullable=False
    )

    risk_level = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        default="New"
    )

    source_ip = Column(
        String,
        nullable=True
    )

    source_country = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    evidence_hash = Column(
        String,
        nullable=True
    )

    blockchain_tx = Column(
        String,
        nullable=True
    )


# ============================================================
# INCIDENT TABLE
# ============================================================

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    threat_id = Column(
        Integer,
        nullable=False
    )

    status = Column(
        String,
        default="Open"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    resolved_at = Column(
        DateTime,
        nullable=True
    )


# ============================================================
# CREATE TABLES
# ============================================================

def create_tables():
    Base.metadata.create_all(
        bind=engine
    )


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    db: Session = SessionLocal()

    try:
        yield db

    finally:
        db.close()