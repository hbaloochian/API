import os
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional

app = FastAPI(title="سامانه ثبت تخلفات ماموران")

# خواندن کلید امنیتی از متغیرهای محیطی Render
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-dev-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

security = HTTPBearer()

class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str

class ViolationCreate(BaseModel):
    plate_number: str
    violation_code: str
    location_lat: float
    location_lng: float

def create_tokens(officer_id: str, device_id: str):
    now = datetime.now(timezone.utc)
    access_payload = {
        "sub": officer_id,
        "role": "officer",
        "device_id": device_id,
        "type": "access",
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    refresh_payload = {
        "sub": officer_id,
        "device_id": device_id,
        "type": "refresh",
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    }
    return (
        jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM),
        jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)
    )

def get_current_officer(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    x_device_id: Optional[str] = Header(None)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="نوع توکن نامعتبر است.")
        if payload.get("role") != "officer":
            raise HTTPException(status_code=403, detail="شما مجوز ثبت تخلف ندارید.")
        if not x_device_id or payload.get("device_id") != x_device_id:
            raise HTTPException(status_code=401, detail="دستگاه ارسال‌کننده نامعتبر است.")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="توکن منقضی شده است.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="توکن نامعتبر است.")

# مسیر بررسی سلامت سرویس (مورد نیاز Render)
@app.get("/")
def health_check():
    return {"status": "online", "service": "Violations API"}

@app.post("/api/v1/auth/login")
def officer_login(data: LoginRequest):
    if data.username == "officer_99" and data.password == "StrongPass@123":
        access_token, refresh_token = create_tokens("OFF_99", data.device_id)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    raise HTTPException(status_code=401, detail="کد پرسنلی یا رمز عبور اشتباه است.")

@app.post("/api/v1/auth/refresh")
def refresh_access_token(refresh_token: str, x_device_id: str = Header(...)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh" or payload.get("device_id") != x_device_id:
            raise HTTPException(status_code=401, detail="Refresh Token نامعتبر است.")
        new_access, new_refresh = create_tokens(payload["sub"], x_device_id)
        return {"access_token": new_access, "refresh_token": new_refresh}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="توکن تمدید نامعتبر یا منقضی است.")

@app.post("/api/v1/violations")
def submit_violation(violation: ViolationCreate, officer: dict = Depends(get_current_officer)):
    return {
        "status": "success",
        "message": "تخلف با موفقیت ثبت شد.",
        "officer_id": officer["sub"],
        "plate": violation.plate_number
    }
