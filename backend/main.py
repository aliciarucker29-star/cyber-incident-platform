from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any
from ai_service import generate_local_summary, generate_ai_summary
import psycopg
import os
import json
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

class EventCreate(BaseModel):
   event_timestamp: datetime
   event_type: str
   action: Optional[str] = None
   username: Optional[str] = None
   source_ip: Optional[str] = None
   hostname: Optional[str] = None
   severity: Optional[str] = None
   source_system: Optional[str] = None
   raw_event: dict[str, Any]

app = FastAPI(
   title="Automated Cyber Incident Investigation Platform",
   version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
   return {
      "status": "healthy",
      "service": "cyber-incident-api"
   }

@app.get("/db-test")
def database_test():
    try:
      with psycopg.connect(
        host="localhost",
        dbname="cyber_incident_db",
        user="postgres",
        password=os.getenv("DB_PASSWORD")
     ) as conn:
         with conn.cursor() as cur:
           cur.execute("SELECT current_database();")
           database = cur.fetchone()[0]

      return {
          "status": "connected",
          "database": database
        }

    except Exception as e:
        return {
          "status": "error",
          "message": str(e)
        }

@app.post("/events")
def create_event(event: EventCreate):
    try:
        with psycopg.connect(
            host="localhost",
            dbname="cyber_incident_db",
            user="postgres",
            password=os.getenv("DB_PASSWORD")
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO events (
                        event_timestamp,
                        event_type,
                        action,
                        username,
                        source_ip,
                        hostname,
                        severity,
                        source_system,
                        raw_event
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING event_id;
                    """,
                    (
                        event.event_timestamp,
                        event.event_type,
                        event.action,
                        event.username,
                        event.source_ip,
                        event.hostname,
                        event.severity,
                        event.source_system,
                        psycopg.types.json.Jsonb(event.raw_event)
                    )
               )

                event_id = cur.fetchone()[0]

        return {
            "status": "created",
            "event_id": event_id
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/events/batch")
def create_events_batch(events: list[EventCreate]):
    created_event_ids = []

    try:
        with psycopg.connect(
            host="localhost",
            dbname="cyber_incident_db",
            user="postgres",
            password=os.getenv("DB_PASSWORD")
        ) as conn:

            with conn.cursor() as cur:
                for event in events:
                    cur.execute(
                        """
                        INSERT INTO events (
                            event_timestamp,
                            event_type,
                            action,
                            username,
                            source_ip,
                            hostname,
                            severity,
                            source_system,
                            raw_event
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING event_id;
                        """,
                        (
                            event.event_timestamp,
                            event.event_type,
                            event.action,
                            event.username,
                            event.source_ip,
                            event.hostname,
                            event.severity,
                            event.source_system,
                            psycopg.types.json.Jsonb(event.raw_event)
                        )
                   )

                    event_id = cur.fetchone()[0]
                    created_event_ids.append(event_id)

            return {
                "status": "created",
                "count": len(created_event_ids),
                "event_ids": created_event_ids
            }

    except Exception as e:
           return {
               "status": "error",
               "message": str(e)
           }


@app.get("/events")
def get_events():
    try:
        with psycopg.connect(
            host="localhost",
            dbname="cyber_incident_db",
            user="postgres",
            password=os.getenv("DB_PASSWORD")

        ) as conn:

            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        event_id,
                        event_timestamp,
                        event_type,
                        action,
                        username,
                        source_ip,
                        hostname,
                        severity,
                        source_system
                   FROM events
                   ORDER BY event_timestamp ASC
               """)

                rows = cur.fetchall()

                events = []

                for row in rows:
                    events.append({
                        "event_id": row[0],
                        "event_timestamp": row[1].isoformat(),
                        "event_type": row[2],
                        "action": row[3],
                        "username": row[4],
                        "source_ip": str(row[5]) if row[5] else None,
                        "hostname": row[6],
                        "severity": row[7],
                        "source_system": row[8]
                   })

                return events

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.get("/events/export")
def export_events():

    try:
       with psycopg.connect(
           host="localhost",
           dbname="cyber_incident_db",
           user="postgres",
           password=os.getenv("DB_PASSWORD")
       ) as conn:
           with conn.cursor() as cur:
               cur.execute("""
                   SELECT
                       event_id,
                       event_timestamp,
                       event_type,
                       action,
                       username,
                       source_ip,
                       hostname,
                       severity,
                       source_system
                  FROM events
                  ORDER BY event_timestamp ASC
             """)

               rows = cur.fetchall()

               events = []

               for row in rows:
                   events.append({
                       "event_id": row[0],
                       "event_timestamp": row[1].isoformat(),
                       "event_type": row[2],
                       "action": row[3],
                       "username": row[4],
                       "source_ip": str(row[5]) if row[5] else "",
                       "hostname": row[6] or "",
                       "severity": row[7] or "",
                       "source_system": row[8] or ""
                })

           return {
               "count": len(events),
               "events": events
               }

    except Exception as e:
           return {
               "status": "error",
               "message": str(e)
           }

def load_investigation_results():
    results_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "investigation-engine",
        "investigation_results.json"
    )

    results_path = os.path.abspath(results_path)

    if not os.path.exists(results_path):
        return None

    with open(results_path, "r", encoding="utf-8") as file:
        return json.load(file)



@app.get("/incidents")
def get_incidents():
    try:
        results_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "investigation-engine",
            "investigation_results.json"
        )

        with open(results_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        # C++ currently exports the incidents as a top-level JSON array.
        if isinstance(data, list):
            incidents = data
        else:
            incidents = data.get("incidents", [])

        return {
            "count": len(incidents),
            "incidents": incidents
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "investigation_results.json was not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    try:
        results_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "investigation-engine",
            "investigation_results.json"
        )

        with open(results_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            incidents = data
        else:
            incidents = data.get("incidents", [])

        for incident in incidents:
            if incident.get("incident_id") == incident_id:
                return incident

        return {
            "status": "error",
            "message": f"Incident {incident_id} not found"
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "investigation_results.json was not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: int):
    try:
        results_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "investigation-engine",
            "investigation_results.json"
        )

        with open(results_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            incidents = data
        else:
            incidents = data.get("incidents", [])

        for incident in incidents:
            if incident.get("incident_id") == incident_id:
                timeline = incident.get("timeline", [])

                return {
                    "incident_id": incident_id,
                    "count": len(timeline),
                    "timeline": timeline
                }

        return {
            "status": "error",
            "message": f"Incident {incident_id} not found"
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "investigation_results.json was not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.get("/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: int):
    try:
        data = load_investigation_results()

        incidents = data

        for incident in incidents:
            if incident.get("incident_id") == incident_id:
                timeline = incident.get("timeline", [])

                return {
                    "incident_id": incident_id,
                    "count": len(timeline),
                    "evidence": timeline
                }

        return {
            "status": "error",
            "message": "Incident not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/incidents/{incident_id}/indicators")
def get_incident_indicators(incident_id: int):
    try:
        data = load_investigation_results()

        if isinstance(data, dict):
            incidents = data.get("incidents", [])
        else:
            incidents = data

        for incident in incidents:
            if incident.get("incident_id") == incident_id:
                indicators = incident.get("indicators", [])

                return {
                    "incident_id": incident_id,
                    "count": len(indicators),
                    "indicators": indicators
                }

        return {
            "status": "error",
            "message": f"Incident {incident_id} not found"
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "investigation_results.json was not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/investigations")
def create_investigation(incident_id: int):
    try:
        data = load_investigation_results()

        if isinstance(data, dict):
            incidents = data.get("incidents", [])

        else:
            incidents = data

        for incident in incidents:
            if incident.get("incident_id") == incident_id:
                result = generate_ai_summary(incident)

                return {
                    "status": "success",
                    "investigation": result
                }

        return {
            "status": "error",
            "message": f"Incident {incident_id} not found"
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "investigation_results.json was not found"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
