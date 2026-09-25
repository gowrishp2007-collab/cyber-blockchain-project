from collections import Counter

from sqlalchemy.orm import Session

from backend.database import Incident, Threat


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

def get_summary(db: Session):
    total_threats = db.query(Threat).count()

    high_risk = (
        db.query(Threat)
        .filter(
            Threat.risk_level.in_(
                ["HIGH", "CRITICAL"]
            )
        )
        .count()
    )

    open_incidents = (
        db.query(Incident)
        .filter(Incident.status == "Open")
        .count()
    )

    resolved_incidents = (
        db.query(Incident)
        .filter(Incident.status == "Resolved")
        .count()
    )

    return {
        "total_threats": total_threats,
        "high_risk_threats": high_risk,
        "open_incidents": open_incidents,
        "resolved_incidents": resolved_incidents,
    }


# ============================================================
# THREAT TYPE DISTRIBUTION
# ============================================================

def get_threat_types(db: Session):
    threats = db.query(Threat).all()

    counts = {}

    for threat in threats:
        threat_type = threat.threat_type

        counts[threat_type] = (
            counts.get(threat_type, 0) + 1
        )

    return counts


# ============================================================
# RISK LEVEL DISTRIBUTION
# ============================================================

def get_risk_levels(db: Session):
    threats = db.query(Threat).all()

    counts = {}

    for threat in threats:
        risk_level = threat.risk_level

        counts[risk_level] = (
            counts.get(risk_level, 0) + 1
        )

    return counts


# ============================================================
# DAILY THREAT TRENDS
# ============================================================

def get_trends(db: Session):
    threats = db.query(Threat).all()

    daily_counts = Counter()

    for threat in threats:
        if threat.created_at:
            date_key = threat.created_at.strftime(
                "%Y-%m-%d"
            )

            daily_counts[date_key] += 1

    return [
        {
            "date": date,
            "threat_count": count,
        }
        for date, count in sorted(
            daily_counts.items()
        )
    ]


# ============================================================
# RECENT ATTACKS
# ============================================================

def get_recent_attacks(
    db: Session,
    limit: int = 10,
):
    threats = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .limit(limit)
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
# ATTACK SOURCES
# ============================================================

def get_attack_sources(db: Session):
    threats = (
        db.query(Threat)
        .filter(Threat.source_ip.isnot(None))
        .all()
    )

    counts = {}

    for threat in threats:
        source = threat.source_ip

        counts[source] = (
            counts.get(source, 0) + 1
        )

    return counts


# ============================================================
# INCIDENT DASHBOARD
# ============================================================

def get_incident_dashboard(db: Session):
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