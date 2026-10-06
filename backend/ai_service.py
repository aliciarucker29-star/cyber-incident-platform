import json
from typing import Any, Dict
from openai import OpenAI


def build_investigation_context(incident: Dict[str, Any]) -> str:
    """
    Convert structured incident evidence into a controlled context
    that can later be supplied to an LLM.

    The AI should explain the evidence produced by the investigation
    engine, not invent new detections.
    """

    context = {
        "incident_id": incident.get("incident_id"),
        "username": incident.get("username"),
        "source_ip": incident.get("source_ip"),
        "hostname": incident.get("hostname"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "risk_level": incident.get("risk_level"),
        "risk_reasons": incident.get("risk_reasons", []),
        "mitre_attack": incident.get("mitre_attack", []),
        "indicators": incident.get("indicators", []),
        "timeline": incident.get("timeline", []),
    }

    return json.dumps(context, indent=2)


def generate_local_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a deterministic investigation summary from the
    structured evidence.

    This gives us a working AI-service interface before connecting
    an external LLM API.
    """

    incident_id = incident.get("incident_id", "unknown")
    username = incident.get("username", "unknown")
    source_ip = incident.get("source_ip", "unknown")
    hostname = incident.get("hostname", "unknown")
    risk_score = incident.get("risk_score", 0)
    risk_level = incident.get("risk_level", "unknown")

    timeline = incident.get("timeline", [])
    indicators = incident.get("indicators", [])
    mitre_attack = incident.get("mitre_attack", [])
    risk_reasons = incident.get("risk_reasons", [])

    summary = (
        f"Incident {incident_id} involves user {username} "
        f"on host {hostname} with source IP {source_ip}. "
        f"The investigation engine assigned a risk score of "
        f"{risk_score} with risk level {risk_level}. "
        f"The incident contains {len(timeline)} timeline events, "
        f"{len(indicators)} extracted indicators, and "
        f"{len(mitre_attack)} MITRE ATT&CK mappings."
    )

    return {
        "incident_id": incident_id,
        "summary": summary,
        "risk_reasons": risk_reasons,
        "mitre_attack": mitre_attack,
        "evidence_event_count": len(timeline),
        "indicator_count": len(indicators),
        "generation_mode": "local_evidence_summary",
    }

def generate_ai_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an evidence-grounded incident investigation summary
    using the OpenAI API.
    """

    client = OpenAI()

    evidence = build_investigation_context(incident)

    instructions = """
You are a cybersecurity incident investigation assistant.

Analyze only the structured incident evidence provided to you.

Rules:
1. Do not invent events, indicators, users, hosts, IP addresses,
   detections, or MITRE ATT&CK mappings.
2. Treat the C++ investigation engine as the authority for detections,
   risk scoring, and ATT&CK mappings.
3. Clearly distinguish observed evidence from interpretation.
4. Do not claim an account or system was compromised unless the
   evidence proves it.
5. If evidence is insufficient, explicitly say so.
6. Explain why the incident received its risk score.
7. Summarize the most important timeline activity.
8. Provide reasonable next investigation steps based on the evidence.

Return a concise cybersecurity analyst-style investigation summary.
"""

    response = client.responses.create(
        model="gpt-6-luna",
        instructions=instructions,
        input=evidence
    )

    return {
        "incident_id": incident.get("incident_id"),
        "summary": response.output_text,
        "generation_mode": "openai_evidence_grounded",
        "evidence_event_count": len(incident.get("timeline", [])),
        "indicator_count": len(incident.get("indicators", [])),
    }