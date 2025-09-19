from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import uvicorn
from fastapi.middleware.cors import CORSMiddleware 
# Import your existing phishing detector
from page_phishing import WebpagePhishingDetector

# -----------------
# Pydantic Models for API Input/Output
# -----------------
class URLInput(BaseModel):
    url: str

class PhishingResponse(BaseModel):
    url: str
    prediction: int  # 0 = legit, 1 = phishing
    risk_score: float  # 0-100 scale (combined_risk_score * 100)
    red_flags: List[str]


# -----------------
# FastAPI Application
# -----------------
app = FastAPI(
    title="Webpage Phishing Detection API",
    description="API to detect phishing websites based on webpage content analysis",
    version="1.0.0"
)

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://172.16.45.127:8001",
    # Add your frontend domain here when deploying
    # "https://your-frontend-domain.com" 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods
    allow_headers=["*"], # Allows all headers
)
# Initialize the detector globally
detector = WebpagePhishingDetector()

# Thread pool for running blocking operations
executor = ThreadPoolExecutor(max_workers=4)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_phishing_detection(url: str) -> dict:
    """
    Wrapper function to run phishing detection in thread pool
    """
    try:
        result = detector.detect_webpage_phishing(url)
        return result
    except Exception as e:
        logger.error(f"Error in phishing detection for {url}: {str(e)}")
        raise e

@app.post("/predict/", response_model=PhishingResponse)
async def predict_phishing(data: URLInput):
    """
    Receives a URL, analyzes webpage content, and returns phishing prediction with risk score.
    
    Args:
        data: URLInput containing the URL to analyze
        
    Returns:
        PhishingResponse with prediction, risk score, and red flags
    """
    url = data.url.strip()
    
    # Basic URL validation
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Run the phishing detection in a thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, run_phishing_detection, url)
        
        # Handle error in result
        if "error" in result:
            raise HTTPException(status_code=422, detail=f"Analysis failed: {result['error']}")
        
        # Extract relevant information from result
        is_phishing = result.get('is_phishing', False)
        combined_risk_score = result.get('combined_risk_score', 0.0)
        confidence = result.get('confidence', 0.0)
        
        # Convert risk score to 0-100 scale
        risk_score_100 = round(combined_risk_score * 100, 2)
        
        # Extract red flags from different analysis components
        red_flags = []
        
        # Add LLM analysis red flags
        llm_analysis = result.get('llm_analysis', {})
        if 'content_red_flags' in llm_analysis:
            red_flags.extend(llm_analysis['content_red_flags'])
        
        # Add primary tactics from LLM
        if 'primary_tactics' in llm_analysis:
            red_flags.extend([f"Tactic: {tactic}" for tactic in llm_analysis['primary_tactics']])
        
        # Add content analysis risk factors
        content_analysis = result.get('content_analysis', {})
        if 'risk_factors' in content_analysis:
            for factor, score in content_analysis['risk_factors'].items():
                if score > 0.1:  # Only include significant risk factors
                    red_flags.append(f"{factor.replace('_', ' ').title()}: {score:.2f}")
        
        # Add webpage features that are suspicious
        webpage_features = result.get('webpage_features', {})
        
        # Add domain reputation issues
        domain_reputation = result.get('domain_reputation', {})
        if domain_reputation.get('reputation_score', 0.5) >= 0.8:
            red_flags.extend([f"Domain: {reason}" for reason in domain_reputation.get('reputation_reason', [])])
        
        # Remove duplicates and limit number of red flags
        red_flags = list(dict.fromkeys(red_flags))[:4]  # Keep unique flags, max 4
        
        # Convert boolean prediction to int
        prediction = 1 if is_phishing else 0
        
        return PhishingResponse(
            url=url,
            prediction=prediction,
            risk_score=risk_score_100,
            red_flags=red_flags
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error analyzing {url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "webpage-phishing-detector"}

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Webpage Phishing Detection API",
        "endpoints": {
            "predict": "/predict/ (POST)",
            "health": "/health (GET)",
            "docs": "/docs (GET)"
        },
        "usage": "Send POST request to /predict/ with {'url': 'example.com'}"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)