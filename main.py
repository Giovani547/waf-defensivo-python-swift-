# ============================================================================
# WAF DEFENSIVO PYTHON + SWIFT - PROYECTO FINAL
# Autor: Giovani Martinez Guzmán | GitHub: Giovani547
# LinkedIn: https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315
# Fibotech - QA Automation | Ciberseguridad México CURP/RFC | Swift Secure Enclave
# 7 años de experiencia | OWASP Top 10 | AGPL-3.0
# ============================================================================

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import re
import logging
import hashlib
from datetime import datetime

# --- CONFIGURACIÓN PRO ---
app = FastAPI(
    title="WAF Defensivo México - Martinez Guzman",
    description="WAF para prevención robo identidad CURP/RFC - Python + Swift Secure Enclave",
    version="2.0.0",
    contact={"name": "Giovani Martinez Guzmán", "url": "https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315"}
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [WAF] - %(message)s')

# --- 1. VALIDACIONES OFICIALES MÉXICO ---
CURP_REGEX = r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}$"
RFC_REGEX = r"^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$"

# --- 2. WAF ENGINE - OWASP TOP 10 ---
RULES = {
    "SQLi": [r"union\s+select", r"or\s+1=1", r"drop\s+table", r"'--", r"select.*from"],
    "XSS": [r"<script.*?>", r"javascript:", r"onerror\s*=", r"onload\s*=", r"<iframe", r"<img.*onerror"],
    "PathTraversal": [r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"/etc/passwd"],
    "Phishing@": [r"@.*https?:", r"@.*http:", r"login.*@"],
    "CommandInjection": [r";\s*cat", r";\s*ls", r"\|\s*cat", r"&&\s*"]
}

def detect_attack(payload: str) -> tuple[bool, str]:
    payload_low = payload.lower()
    for attack_type, patterns in RULES.items():
        for pat in patterns:
            if re.search(pat, payload_low, re.IGNORECASE):
                return True, f"{attack_type} - {pat}"
    return False, ""

def hash_sensitive(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:10]

# --- 3. MIDDLEWARE WAF CHIDO ---
@app.middleware("http")
async def waf_chido_middleware(request: Request, call_next):
    body = (await request.body()).decode('utf-8', errors='ignore')
    full_payload = f"{request.url.path} {request.url.query} {body}"
    
    is_attack, rule = detect_attack(full_payload)
    if is_attack:
        logging.warning(f"BLOCK IP={request.client.host} RULE={rule} HASH={hash_sensitive(full_payload)}")
        return JSONResponse(
            status_code=403,
            content={
                "bloqueado": True,
                "motivo": rule,
                "waf": "Giovani Martinez Guzmán - Activo",
                "timestamp": datetime.now().isoformat()
            }
        )
    
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Server"] = "WAF-MX-Giovani547"
    return response

# --- 4. ENDPOINTS ---
@app.get("/")
def root():
    return {
        "proyecto": "waf-defensivo-python-swift-",
        "status": "🔥 CHIDO Y ACTIVO",
        "autor": "Giovani Martinez Guzmán",
        "github": "Giovani547",
        "linkedin": "https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315",
        "stack": ["Python", "FastAPI", "Swift Secure Enclave", "MySQL", "OWASP"],
        "version": "2.0"
    }

@app.post("/api/v1/validar-identidad")
def validar_identidad(curp: str, rfc: str):
    curp = curp.upper().strip()
    rfc = rfc.upper().strip()
    
    if not re.match(CURP_REGEX, curp):
        raise HTTPException(status_code=400, detail={"error": "CURP inválida", "formato": "AAAA######HAAAAA##"})
    if not re.match(RFC_REGEX, rfc):
        raise HTTPException(status_code=400, detail={"error": "RFC inválido", "formato": "AAA######AAA"})
    
    return {
        "validacion": "exitosa",
        "curp_hash": hash_sensitive(curp),
        "rfc_hash": hash_sensitive(rfc),
        "proteccion_activa": True,
        "mensaje": "Formato válido - Datos protegidos con WAF"
    }

@app.get("/health")
def health_check():
    return {"waf": "chido", "owasp": "protegido", "autor": "Giovani Martinez Guzmán", "uptime": "ok"}

@app.get("/swift-secure-enclave")
def swift_info():
    return {
        "ios": "Secure Enclave integrado",
        "descripcion": "Biometría + Keychain + WAF",
        "swift_code": "let context = LAContext() // FaceID protegida - Giovani Martinez Guzman"
    }