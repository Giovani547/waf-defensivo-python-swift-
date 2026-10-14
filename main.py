# Proyecto: WAF Defensivo - Prevención de Robo de Identidad (México)
# Autor: Giovani Martinez Guzman
# LinkedIn: https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315
# GitHub: Giovani547/waf-defensivo-python-swift
# Stack: Python FastAPI + iOS Swift (Secure Enclave / FaceID)
# Enfoque: OWASP Top 10 - Proyecto 100% Defensivo y Educativo
# Certificación: LinkedIn > Licencias y certificaciones

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re
from cryptography.fernet import Fernet
import logging

app = FastAPI(
    title="WAF Defensivo México",
    description="Proyecto de Giovani Martinez - https://https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315",
    version="1.0"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WAF")

key = Fernet.generate_key()
cipher = Fernet(key)

# Patrones oficiales México
CURP_REGEX = r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}$"
RFC_REGEX = r"^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$"

ATTACK_PATTERNS = {
    "sql_injection": r"(\bUNION\b|\bSELECT\b|--|\bOR\b\s+\d+=\d+)",
    "xss": r"(<script|javascript:|onerror=)",
    "path_traversal": r"(\.\./|etc/passwd)",
    "command_injection": r"(\|\s*cat|;.*ls)"
}

def detect_attack(payload: str):
    for name, pattern in ATTACK_PATTERNS.items():
        if re.search(pattern, payload, re.IGNORECASE):
            return name
    return None

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    body = await request.body()
    body_str = body.decode(errors="ignore")
    attack = detect_attack(body_str + str(request.url))
    if attack:
        logger.warning(f"Bloqueado: {attack} - {request.client.host}")
        return JSONResponse(status_code=403, content={"status": "blocked", "waf": attack})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000"
    return response

@app.post("/validar")
async def validar_datos(curp: str, rfc: str):
    # Defensa anti-phishing técnica del @
    if "@" in curp or "@" in rfc:
        return {"valid": False, "error": "Posible phishing con @"}
    
    curp_valid = bool(re.match(CURP_REGEX, curp.upper()))
    rfc_valid = bool(re.match(RFC_REGEX, rfc.upper()))
    
    if curp_valid and rfc_valid:
        data_encrypted = cipher.encrypt(f"{curp}|{rfc}".encode())
        logger.info("Validación OK - cifrado aplicado")
        return {"valid": True, "encrypted": True, "linkedin": "https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315"}
    
    return {"valid": False, "curp_ok": curp_valid, "rfc_ok": rfc_valid}

@app.get("/")
def health():
    return {
        "status": "WAF Activo", 
        "autor": "Giovani Martinez Guzman",
        "linkedin": "https://https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315",
        "owasp": "Protegido"
    }