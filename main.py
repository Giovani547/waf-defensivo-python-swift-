# waf-defensivo-python-swift-
# Autor: Giovani Martinez Guzman - Giovani547
# LinkedIn:https://www.linkedin.com/in/giovani-martinez-guzm%C3%A1n-a119a7315
# Enfoque 100% defensivo - OWASP Top 10 - Prevención de robo de identidad

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import re
import logging
from datetime import datetime

app = FastAPI(title="WAF Defensivo - Prevención Robo Identidad", version="1.0")

# Headers de seguridad
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# --- VALIDACIONES MEXICO ---
CURP_REGEX = r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}$"
RFC_REGEX = r"^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$"

def validar_curp(curp: str) -> bool:
    return bool(re.match(CURP_REGEX, curp.upper().strip()))

def validar_rfc(rfc: str) -> bool:
    return bool(re.match(RFC_REGEX, rfc.upper().strip()))

# --- WAF - DETECCIÓN DEFENSIVA ---
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"union.*select", r"select.*from", r"drop.*table"
]
XSS_PATTERNS = [
    r"<script.*?>", r"javascript:", r"onerror=", r"onload=",
    r"<iframe", r"<img.*src"