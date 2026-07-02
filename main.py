from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from engine import scan
from ai_layer import explain

app = FastAPI(title="LinkDecoder API")

# Allow the frontend (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    result = scan(req.url)
    result["ai_explanation"] = explain(result)
    return result