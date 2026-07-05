import os
import sys
import logging
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pythonjsonlogger import jsonlogger
from fastapi.concurrency import run_in_threadpool
from typing import Optional

# Add parent directory of services to path if running directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.url_classifier import predict_url
from services.email_classifier import predict_sender_email

# Configure JSON structured logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Setup Rate Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute", "5/second"])
app = FastAPI(title="Arcis Multi-Model API Node")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Configure CORS (avoid wildcards in production)
allowed_origins_raw = os.environ.get("ARCIS_ALLOWED_ORIGINS", "")
if allowed_origins_raw:
    allowed_origins = [o.strip() for o in allowed_origins_raw.split(",")]
else:
    # Local dev allows wide access, production restricts to local origins/frontend
    allowed_origins = ["*"] if os.environ.get("ENV") != "production" else ["https://arcis-dvgq.onrender.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Authentication configuration
from fastapi.security import APIKeyHeader
from fastapi import Depends
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
API_KEY = os.environ.get("ARCIS_API_KEY")
if not API_KEY:
    raise RuntimeError("CRITICAL CONFIGURATION ERROR: ARCIS_API_KEY environment variable must be set.")

async def verify_api_key(request: Request, api_key: Optional[str] = Depends(API_KEY_HEADER)):
    # 1. If key matches exactly, allow request
    if api_key and api_key == API_KEY:
        return api_key

    # 2. Check if request is same-origin or localhost bypass
    referer = request.headers.get("referer")
    origin = request.headers.get("origin")
    host = request.headers.get("host") or f"localhost:{os.environ.get('PORT', 5001)}"

    # Determine caller netloc
    from urllib.parse import urlparse
    caller_netloc = ""
    if referer:
        caller_netloc = urlparse(referer).netloc
    elif origin:
        caller_netloc = urlparse(origin).netloc

    # Bypass auth if Referer/Origin matches the current Host, or if caller is localhost
    if caller_netloc:
        if caller_netloc == host or caller_netloc.startswith("localhost:") or caller_netloc.startswith("127.0.0.1:"):
            return "same-origin-bypass"

    raise HTTPException(status_code=403, detail="Invalid or missing API Key")

# Add Security Headers Middleware (Strict CSP without unsafe-inline)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Pydantic Schemas with strong email validation and length limits
class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", min_length=1, max_length=2048)

class EmailAnalysisRequest(BaseModel):
    email: Optional[EmailStr] = Field(None, description="Sender email address")
    sender: Optional[EmailStr] = Field(None, description="Fallback for sender email address")
    subject: str = Field("", description="Email subject", max_length=500)
    body: str = Field("", description="Email body text", max_length=50000)
    reply_to: Optional[str] = Field("", description="Reply-To email address") # Keep str to allow empty replies
    spf: str = Field("none", description="SPF verification result")
    dkim: str = Field("none", description="DKIM verification result")
    dmarc: str = Field("none", description="DMARC verification result")

@app.post("/api/analyze/url", dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def analyze_url(request: Request, payload: UrlAnalysisRequest):
    url = payload.url.strip()
    client_ip = get_remote_address(request)
    
    # Safe logging to protect PII
    from urllib.parse import urlparse
    try:
        parsed_url = urlparse(url)
        safe_url = f"{parsed_url.scheme}://{parsed_url.netloc}/..."
    except Exception:
        safe_url = "[Invalid URL]"
    
    logger.info(f"Analyzing URL: {safe_url} from client {client_ip}")
    try:
        # Offload blocking ML and network task to threadpool
        result = await run_in_threadpool(predict_url, url)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error analyzing URL {safe_url}", exc_info=True)
        # Avoid leaking internal stack trace details to client
        raise HTTPException(status_code=500, detail="Internal server error during URL analysis")

@app.post("/api/analyze/email", dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def analyze_email(request: Request, payload: EmailAnalysisRequest):
    email_obj = payload.email or payload.sender
    email = str(email_obj).strip() if email_obj else ""
    if not email:
        raise HTTPException(status_code=400, detail="Missing or empty 'email' parameter")

    client_ip = get_remote_address(request)
    
    # Safe logging to protect PII
    safe_email = f"***@{email.split('@')[1]}" if "@" in email else "[Invalid Email]"
    logger.info(f"Analyzing Email: {safe_email} from client {client_ip}")
    
    # Validate reply_to if present
    reply_to_email = payload.reply_to.strip()
    if reply_to_email:
        import re
        EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
        if not EMAIL_RE.match(reply_to_email):
            raise HTTPException(status_code=400, detail="Invalid Reply-To email address")

    try:
        # Offload blocking ML and network task to threadpool
        result = await run_in_threadpool(
            predict_sender_email,
            email_address=email,
            subject=payload.subject,
            body=payload.body,
            reply_to=reply_to_email,
            spf=payload.spf,
            dkim=payload.dkim,
            dmarc=payload.dmarc
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error analyzing Email {safe_email}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during Email analysis")

@app.get("/api/health")
async def health_check(request: Request):
    # Only expose deployment regions and models when authorized
    api_key = request.headers.get("X-API-Key")
    if api_key == API_KEY:
        return {
            "status": "healthy", 
            "node": "US-EAST-1",
            "models": {
                "url_classifier": "LightGBM_Tuned",
                "email_classifier": "XGBoost_ONNX"
            },
            "framework": "FastAPI"
        }
    return {"status": "healthy"}

@app.get("/api/config")
async def get_client_config():
    """
    Intentionally disabled returning the real API key to prevent exposing it publicly.
    Same-origin/localhost requests bypass the key check, while external requests (like the Chrome Extension)
    use the user-configured API key in the extension's settings.
    """
    return {"api_key_required": True, "api_key": None}

import uuid
reports_db = {}

@app.post("/api/report", dependencies=[Depends(verify_api_key)])
async def create_report(payload: dict):
    # Bound the size of reports_db in memory to prevent memory exhaustion (FIFO eviction)
    if len(reports_db) > 1000:
        oldest_key = next(iter(reports_db))
        reports_db.pop(oldest_key, None)
    
    report_id = str(uuid.uuid4())
    reports_db[report_id] = payload
    return {"report_id": report_id}

@app.get("/api/report/{report_id}", dependencies=[Depends(verify_api_key)])
async def get_report(report_id: str):
    if report_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    return reports_db[report_id]

from fastapi.staticfiles import StaticFiles

# Serve frontend static files from the root URL
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

@app.get("/team")
async def get_team():
    team_path = os.path.join(frontend_dir, "team.html")
    if os.path.exists(team_path):
        return FileResponse(team_path)
    raise HTTPException(status_code=404, detail="Team page not found")

if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == '__main__':
    import uvicorn
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting Arcis Multi-Model API Node on port {port}...")
    uvicorn.run("main:app", host='0.0.0.0', port=port, reload=False)
