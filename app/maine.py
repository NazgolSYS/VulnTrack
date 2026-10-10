from fastapi import FastAPI

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