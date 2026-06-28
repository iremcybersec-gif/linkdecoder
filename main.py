from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from engine import scan

app = FastAPI(title="LinkDecoder API")

# Allow the frontend (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # tighten to your frontend URL before demo if you want
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


@app.get("/")
def health():
    return {"status": "LinkDecoder API is running"}


@app.post("/scan")
def scan_url(req: ScanRequest):
    return scan(req.url)