from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.blockchain import (
    generate_evidence_hash,
    get_threat_from_blockchain,
    record_threat_on_blockchain,
)

from backend.dashboard import (
    get_attack_sources,
    get_incident_dashboard,
    get_recent_attacks,
    get_risk_levels,
    get_summary,
    get_threat_types,
    get_trends,
)

from backend.database import (
    Incident,
    Threat,
    create_tables,
    get_db,
)

from backend.threat_analysis import analyze_threat


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Cyber Blockchain API",
    version="1.0.0",
    description=(
        "Blockchain-Based Cyber Threat Intelligence "
        "and Tamper-Proof Incident Management System"
    ),
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODELS
# ============================================================

class ThreatRequest(BaseModel):
    threat_type: str
    threat_value: str


class IncidentRequest(BaseModel):
    threat_id: int


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.on_event("startup")
def startup():
    create_tables()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "Cyber Blockchain API is running",
        "status": "online",
    }


# ============================================================
# CREATE THREAT
# ============================================================

@app.post("/threat")
def create_threat(
    request: ThreatRequest,
    db: Session = Depends(get_db),
):
    threat_type = request.threat_type.strip().lower()
    threat_value = request.threat_value.strip()

    # --------------------------------------------------------
    # Validate threat type
    # --------------------------------------------------------

    if threat_type not in {"ip", "url", "hash"}:
        raise HTTPException(
            status_code=400,
            detail="threat_type must be ip, url, or hash",
        )

    # --------------------------------------------------------
    # Validate threat value
    # --------------------------------------------------------

    if not threat_value:
        raise HTTPException(
            status_code=400,
            detail="threat_value cannot be empty",
        )

    # --------------------------------------------------------
    # Threat analysis
    # --------------------------------------------------------

    analysis = analyze_threat(
        threat_type,
        threat_value,
    )

    # --------------------------------------------------------
    # Generate evidence hash
    # --------------------------------------------------------

    evidence = f"{threat_type}:{threat_value}"

    evidence_hash = generate_evidence_hash(
        evidence
    )

    # --------------------------------------------------------
    # Create database record
    # --------------------------------------------------------

    threat = Threat(
        threat_type=threat_type,
        threat_value=threat_value,
        risk_level=analysis["risk_level"],
        status=analysis["result"],
        source_ip=(
            threat_value
            if threat_type == "ip"
            else None
        ),
        evidence_hash=evidence_hash,
    )

    db.add(threat)
    db.commit()
    db.refresh(threat)

    # --------------------------------------------------------
    # Record hash on blockchain
    # --------------------------------------------------------

    try:
        transaction_hash = record_threat_on_blockchain(
            threat.id,
            evidence_hash,
        )

        threat.blockchain_tx = transaction_hash

        db.commit()
        db.refresh(threat)

    except Exception as exc:
        db.delete(threat)
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Blockchain recording failed: {exc}",
        )

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {
        "message": "Threat recorded successfully",
        "threat_id": threat.id,
        "threat_type": threat.threat_type,
        "threat_value": threat.threat_value,
        "result": analysis["result"],
        "risk_level": analysis["risk_level"],
        "reason": analysis["reason"],
        "evidence_hash": evidence_hash,
        "blockchain_tx": transaction_hash,
    }


# ============================================================
# GET ALL THREATS
# ============================================================

@app.get("/threats")
def get_threats(
    db: Session = Depends(get_db),
):
    threats = (
        db.query(Threat)
        .order_by(Threat.id.desc())
        .all()
    )

    return [
        {
            "id": threat.id,
            "threat_type": threat.threat_type,
            "threat_value": threat.threat_value,
            "risk_level": threat.risk_level,
            "status": threat.status,
            "source_ip": threat.source_ip,
            "source_country": threat.source_country,
            "created_at": threat.created_at,
            "evidence_hash": threat.evidence_hash,
            "blockchain_tx": threat.blockchain_tx,
        }
        for threat in threats
    ]


# ============================================================
# GET SINGLE THREAT
# ============================================================

@app.get("/threat/{threat_id}")
def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
):
    threat = (
        db.query(Threat)
        .filter(Threat.id == threat_id)
        .first()
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    return {
        "id": threat.id,
        "threat_type": threat.threat_type,
        "threat_value": threat.threat_value,
        "risk_level": threat.risk_level,
        "status": threat.status,
        "source_ip": threat.source_ip,
        "source_country": threat.source_country,
        "created_at": threat.created_at,
        "evidence_hash": threat.evidence_hash,
        "blockchain_tx": threat.blockchain_tx,
    }


# ============================================================
# VERIFY THREAT
# ============================================================

@app.get("/verify/{threat_id}")
def verify_threat(
    threat_id: int,
    db: Session = Depends(get_db),
):
    threat = (
        db.query(Threat)
        .filter(Threat.id == threat_id)
        .first()
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    # --------------------------------------------------------
    # Generate current hash
    # --------------------------------------------------------

    evidence = (
        f"{threat.threat_type}:{threat.threat_value}"
    )

    current_hash = generate_evidence_hash(
        evidence
    )

    # --------------------------------------------------------
    # Read blockchain record
    # --------------------------------------------------------

    try:
        blockchain_record = (
            get_threat_from_blockchain(
                threat_id
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Blockchain verification failed: {exc}",
        )

    # --------------------------------------------------------
    # Extract blockchain hash
    # --------------------------------------------------------

    blockchain_hash = blockchain_record[1]

    # --------------------------------------------------------
    # Compare
    # --------------------------------------------------------

    is_match = (
        current_hash == blockchain_hash
    )

    # --------------------------------------------------------
    # Return verification result
    # --------------------------------------------------------

    return {
        "threat_id": threat_id,
        "current_hash": current_hash,
        "blockchain_hash": blockchain_hash,
        "verified": is_match,
        "status": (
            "Authentic"
            if is_match
            else "Tampered"
        ),
    }


# ============================================================
# CREATE INCIDENT
# ============================================================

@app.post("/incident")
def create_incident(
    request: IncidentRequest,
    db: Session = Depends(get_db),
):
    threat = (
        db.query(Threat)
        .filter(
            Threat.id == request.threat_id
        )
        .first()
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    incident = Incident(
        threat_id=request.threat_id,
        status="Open",
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident created successfully",
        "incident_id": incident.id,
        "threat_id": incident.threat_id,
        "status": incident.status,
        "created_at": incident.created_at,
    }


# ============================================================
# GET ALL INCIDENTS
# ============================================================

@app.get("/incidents")
def get_incidents(
    db: Session = Depends(get_db),
):
    incidents = (
        db.query(Incident)
        .order_by(Incident.id.desc())
        .all()
    )

    return [
        {
            "id": incident.id,
            "threat_id": incident.threat_id,
            "status": incident.status,
            "created_at": incident.created_at,
            "resolved_at": incident.resolved_at,
        }
        for incident in incidents
    ]


# ============================================================
# GET SINGLE INCIDENT
# ============================================================

@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "id": incident.id,
        "threat_id": incident.threat_id,
        "status": incident.status,
        "created_at": incident.created_at,
        "resolved_at": incident.resolved_at,
    }


# ============================================================
# RESOLVE INCIDENT
# ============================================================

@app.put("/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    incident.status = "Resolved"
    incident.resolved_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident resolved successfully",
        "incident_id": incident.id,
        "status": incident.status,
        "resolved_at": incident.resolved_at,
    }


# ============================================================
# DASHBOARD - SUMMARY
# ============================================================

@app.get("/dashboard/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
):
    return get_summary(db)


# ============================================================
# DASHBOARD - TRENDS
# ============================================================

@app.get("/dashboard/trends")
def dashboard_trends(
    db: Session = Depends(get_db),
):
    return get_trends(db)


# ============================================================
# DASHBOARD - THREAT TYPES
# ============================================================

@app.get("/dashboard/threat-types")
def dashboard_threat_types(
    db: Session = Depends(get_db),
):
    return get_threat_types(db)


# ============================================================
# DASHBOARD - RISK LEVELS
# ============================================================

@app.get("/dashboard/risk-levels")
def dashboard_risk_levels(
    db: Session = Depends(get_db),
):
    return get_risk_levels(db)


# ============================================================
# DASHBOARD - RECENT ATTACKS
# ============================================================

@app.get("/dashboard/recent-attacks")
def dashboard_recent_attacks(
    db: Session = Depends(get_db),
):
    return get_recent_attacks(db)


# ============================================================
# DASHBOARD - ATTACK SOURCES
# ============================================================

@app.get("/dashboard/attack-sources")
def dashboard_attack_sources(
    db: Session = Depends(get_db),
):
    return get_attack_sources(db)


# ============================================================
# DASHBOARD - INCIDENTS
# ============================================================

@app.get("/dashboard/incidents")
def dashboard_incidents(
    db: Session = Depends(get_db),
):
    return get_incident_dashboard(db)