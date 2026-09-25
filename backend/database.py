from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker


DATABASE_URL = "sqlite:///./cyber_threats.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String, nullable=False)
    threat_value = Column(String, nullable=False)
    risk_level = Column(String, nullable=False)
    status = Column(String, default="New")
    source_ip = Column(String, nullable=True)
    source_country = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    evidence_hash = Column(String, nullable=True)
    blockchain_tx = Column(String, nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, nullable=False)
    status = Column(String, default="Open")
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db: Session = SessionLocal()

    try:
        yield db
    finally:
        db.close()