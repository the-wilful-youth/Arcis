import os
import sys
import logging
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
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

# Enable CORS for all routes (including chrome extensions)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Pydantic Schemas
class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", min_length=1)

class EmailAnalysisRequest(BaseModel):
    email: Optional[str] = Field(None, description="Sender email address")
    sender: Optional[str] = Field(None, description="Fallback for sender email address")
    subject: str = Field("", description="Email subject")
    body: str = Field("", description="Email body text")
    reply_to: str = Field("", description="Reply-To email address")
    spf: str = Field("none", description="SPF verification result")
    dkim: str = Field("none", description="DKIM verification result")
    dmarc: str = Field("none", description="DMARC verification result")

@app.post("/api/analyze/url")
@limiter.limit("60/minute")
async def analyze_url(request: Request, payload: UrlAnalysisRequest):
    url = payload.url.strip()
    client_ip = get_remote_address(request)
    logger.info(f"Analyzing URL: {url} from client {client_ip}")
    try:
        # Offload blocking ML and network task to threadpool
        result = await run_in_threadpool(predict_url, url)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error analyzing URL {url}", exc_info=True)
        # Avoid leaking internal stack trace details to client
        raise HTTPException(status_code=500, detail="Internal server error during URL analysis")

@app.post("/api/analyze/email")
@limiter.limit("60/minute")
async def analyze_email(request: Request, payload: EmailAnalysisRequest):
    email = (payload.email or payload.sender or "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="Missing or empty 'email' parameter")

    client_ip = get_remote_address(request)
    logger.info(f"Analyzing Email: {email} from client {client_ip}")
    try:
        # Offload blocking ML and network task to threadpool
        result = await run_in_threadpool(
            predict_sender_email,
            email_address=email,
            subject=payload.subject,
            body=payload.body,
            reply_to=payload.reply_to,
            spf=payload.spf,
            dkim=payload.dkim,
            dmarc=payload.dmarc
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Error analyzing Email {email}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during Email analysis")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy", 
        "node": "US-EAST-1",
        "models": {
            "url_classifier": "LightGBM_Tuned",
            "email_classifier": "XGBoost_ONNX"
        },
        "framework": "FastAPI"
    }

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
