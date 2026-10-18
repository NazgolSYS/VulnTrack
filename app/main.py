
from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers import(
risk_assessments, roles, users, assets, software, vulnerabilities, remediation_tasks,
asset_software, scans, audit_logs
) 


app = FastAPI(
    title="VulnTrack API",
    description="Vulnerability Management and Risk Tracking Platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "VulnTrack API is running"
    }


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))

    return {
        "status": "ok",
        "database": "connected"
    }

app.include_router(risk_assessments.router)
app.include_router(roles.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(software.router)
app.include_router(vulnerabilities.router)
app.include_router(remediation_tasks.router)
app.include_router(asset_software.router)
app.include_router(scans.router)
app.include_router(audit_logs.router)
