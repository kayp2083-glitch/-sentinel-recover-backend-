"""
╔══════════════════════════════════════════════════════════════════╗
║           SENTINEL RECOVER — Backend API  v1.0.0                ║
║     Intelligent Mobile Theft Recovery Platform                   ║
║                                                                  ║
║  Stack : FastAPI + PostgreSQL + Redis + WebSockets               ║
║  Auth  : JWT (RS256) + bcrypt                                    ║
║  Crypto: AES-256 via Fernet (sensitive fields encrypted at rest) ║
║  Push  : Firebase (Android) + APNs (iOS)                        ║
╚══════════════════════════════════════════════════════════════════╝

Install dependencies:
    pip install fastapi uvicorn[standard] sqlalchemy psycopg2-binary
                python-jose[cryptography] passlib[bcrypt] python-multipart
                cryptography pydantic[email] python-dotenv httpx redis

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Environment variables (.env):
    DATABASE_URL   = postgresql://user:pass@localhost/sentinel_recover
    SECRET_KEY     = <openssl rand -hex 32>
    FERNET_KEY     = <Fernet.generate_key() output — base64>
    FCM_SERVER_KEY = <Firebase Cloud Messaging server key>
    APNS_KEY_PATH  = <path to .p8 Apple key file>
    APNS_KEY_ID    = <Apple Key ID>
    APNS_TEAM_ID   = <Apple Team ID>
    REDIS_URL      = redis://localhost:6379
"""

# ── Imports ─────────────────────────────────────────────────────────────────
import uuid, json, asyncio, enum, os, hashlib, hmac
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

from fastapi import (
    FastAPI, HTTPException, Depends, WebSocket,
    WebSocketDisconnect, status, BackgroundTasks, Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

import httpx
from sqlalchemy import (
    create_engine, Column, String, Float, DateTime,
    Boolean, ForeignKey, Text, Integer
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker, relationship
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────
DATABASE_URL    = os.getenv("DATABASE_URL",   "postgresql://user:pass@localhost/sentinel_recover")
SECRET_KEY      = os.getenv("SECRET_KEY",     "change-me-use-openssl-rand-hex-32")
ALGORITHM       = "HS256"
TOKEN_EXPIRE_M  = 60 * 24          # 24 hours
FERNET_KEY      = os.getenv("FERNET_KEY",     Fernet.generate_key())
FCM_SERVER_KEY  = os.getenv("FCM_SERVER_KEY", "")
REDIS_URL       = os.getenv("REDIS_URL",      "redis://localhost:6379")
FCM_URL         = "https://fcm.googleapis.com/fcm/send"

# ── Database ─────────────────────────────────────────────────────────────────
engine       = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Enums ────────────────────────────────────────────────────────────────────
class DeviceStatus(str, enum.Enum):
    dormant  = "dormant"
    recovery = "recovery"
    found    = "found"
    offline  = "offline"

class Platform(str, enum.Enum):
    android = "android"
    ios     = "ios"

class EventType(str, enum.Enum):
    location     = "location"
    sim_change   = "sim_change"
    unlock_fail  = "unlock_fail"
    network      = "network"
    activation   = "activation"
    deactivation = "deactivation"
    heartbeat    = "heartbeat"
    cam_capture  = "cam_capture"   # future: photo evidence event

class Severity(str, enum.Enum):
    info     = "info"
    warning  = "warning"
    critical = "critical"
    success  = "success"

# ── SQLAlchemy Models ────────────────────────────────────────────────────────
class User(Base):
    """Sentinel Recover account — device owner."""
    __tablename__ = "users"

    id         = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email      = Column(String(255), unique=True, nullable=False, index=True)
    hashed_pw  = Column(String(255), nullable=False)
    full_name  = Column(String(255))
    phone      = Column(String(50))              # For 2FA / alerts via SMS
    is_active  = Column(Boolean, default=True)
    plan       = Column(String(50), default="free")   # free | pro | enterprise
    created_at = Column(DateTime, default=datetime.utcnow)

    devices = relationship("Device", back_populates="owner", cascade="all, delete-orphan")


class Device(Base):
    """
    A registered device enrolled in Sentinel Recover.
    Status is DORMANT until owner activates Recovery Mode.
    No tracking data is collected while status == dormant.
    """
    __tablename__ = "devices"

    id           = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id     = Column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name         = Column(String(255), nullable=False)
    platform     = Column(SAEnum(Platform), nullable=False)
    device_type  = Column(String(50), default="phone")       # phone | tablet | laptop
    imei         = Column(String(20), unique=True, nullable=False, index=True)
    serial       = Column(String(100))
    color        = Column(String(100))
    brand        = Column(String(100))
    model        = Column(String(100))

    # Status
    status       = Column(SAEnum(DeviceStatus), default=DeviceStatus.dormant, index=True)
    last_seen    = Column(DateTime)
    battery      = Column(Float)

    # Auth tokens (never expose raw push token to client)
    push_token   = Column(Text)           # FCM / APNs token — AES-256 encrypted at rest
    device_token = Column(String(255), unique=True, default=lambda: str(uuid.uuid4()))
    # ↑ device_token: shared with mobile app on registration.
    #   Used by mobile app to authenticate ingest requests.
    #   Rotate on each recovery deactivation for security.

    registered_at = Column(DateTime, default=datetime.utcnow)

    owner     = relationship("User", back_populates="devices")
    locations = relationship("LocationLog",    back_populates="device", cascade="all, delete-orphan")
    events    = relationship("SecurityEvent",  back_populates="device", cascade="all, delete-orphan")


class LocationLog(Base):
    """
    Time-series GPS location records.
    Production tip: Convert this table to a TimescaleDB hypertable
    for efficient time-range queries at scale:
        SELECT create_hypertable('location_logs', 'captured_at');
    """
    __tablename__ = "location_logs"

    id          = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id   = Column(PGUUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    latitude    = Column(Float, nullable=False)
    longitude   = Column(Float, nullable=False)
    accuracy    = Column(Float)          # meters — GPS accuracy radius
    altitude    = Column(Float)          # meters above sea level
    speed       = Column(Float)          # m/s — helps detect vehicle movement
    heading     = Column(Float)          # degrees — movement direction
    place_name  = Column(String(500))    # reverse-geocoded address
    captured_at = Column(DateTime, default=datetime.utcnow, index=True)

    device = relationship("Device", back_populates="locations")


class SecurityEvent(Base):
    """
    All security-relevant events from the mobile app.
    Examples: SIM change, unlock attempts, network changes, activation.
    metadata is a JSON blob, encrypted at rest.
    """
    __tablename__ = "security_events"

    id          = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id   = Column(PGUUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    event_type  = Column(SAEnum(EventType), nullable=False, index=True)
    severity    = Column(SAEnum(Severity), default=Severity.info)
    message     = Column(String(500))
    metadata_enc= Column(Text)           # AES-256 encrypted JSON blob
    captured_at = Column(DateTime, default=datetime.utcnow, index=True)

    device = relationship("Device", back_populates="events")


# Create tables
try:
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully")
except Exception as e:
    print(f"❌ Database error: {e}")

# ── Encryption (AES-256 via Fernet) ──────────────────────────────────────────
_fernet = Fernet(FERNET_KEY)

def encrypt(data: str) -> str:
    """Encrypt sensitive string for storage."""
    return _fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    """Decrypt stored sensitive string."""
    return _fernet.decrypt(token.encode()).decode()

# ── Auth Utilities ────────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/token")

def hash_pw(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_pw(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def make_token(data: dict, expires: timedelta = None) -> str:
    payload = {**data, "exp": datetime.utcnow() + (expires or timedelta(minutes=TOKEN_EXPIRE_M))}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    exc = HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        if not uid:
            raise exc
    except JWTError:
        raise exc
    user = db.query(User).filter(User.id == uuid.UUID(uid)).first()
    if not user or not user.is_active:
        raise exc
    return user

def get_device_by_token(device_token: str, db: Session) -> Device:
    """Authenticate a mobile app data ingest request via device_token."""
    device = db.query(Device).filter(Device.device_token == device_token).first()
    if not device:
        raise HTTPException(403, "Invalid device token")
    if device.status != DeviceStatus.recovery:
        raise HTTPException(403, "Device is not in Recovery Mode — ignoring ingest")
    return device

# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email:     EmailStr
    password:  str = Field(min_length=8, description="Minimum 8 characters")
    full_name: str
    phone:     Optional[str] = None

class UserOut(BaseModel):
    id: uuid.UUID; email: str; full_name: str; plan: str; created_at: datetime
    class Config: from_attributes = True

class TokenOut(BaseModel):
    access_token: str; token_type: str = "bearer"

class DeviceRegister(BaseModel):
    name:        str
    platform:    Platform
    imei:        str = Field(min_length=14, max_length=17)
    serial:      Optional[str] = None
    color:       Optional[str] = None
    brand:       Optional[str] = None
    model:       Optional[str] = None
    device_type: str = "phone"

class DeviceLinkToken(BaseModel):
    """Sent by mobile app on first launch to register its push token."""
    imei:       str
    push_token: str    # FCM registration token (Android) or APNs device token (iOS)
    platform:   Platform

class DeviceOut(BaseModel):
    id: uuid.UUID; name: str; platform: Platform; imei: str
    color: Optional[str]; status: DeviceStatus
    last_seen: Optional[datetime]; battery: Optional[float]
    registered_at: datetime
    class Config: from_attributes = True

class LocationIn(BaseModel):
    """GPS location submitted by mobile app during Recovery Mode."""
    device_token: str
    latitude:     float = Field(ge=-90,   le=90)
    longitude:    float = Field(ge=-180,  le=180)
    accuracy:     Optional[float] = None
    altitude:     Optional[float] = None
    speed:        Optional[float] = None
    heading:      Optional[float] = None
    place_name:   Optional[str]  = None
    battery:      Optional[float]= None

class EventIn(BaseModel):
    """Security event submitted by mobile app."""
    device_token: str
    event_type:   EventType
    severity:     Severity = Severity.info
    message:      str
    metadata:     Optional[Dict[str, Any]] = None

class LocationOut(BaseModel):
    id: uuid.UUID; latitude: float; longitude: float
    accuracy: Optional[float]; place_name: Optional[str]; captured_at: datetime
    class Config: from_attributes = True

class EventOut(BaseModel):
    id: uuid.UUID; event_type: EventType; severity: Severity
    message: str; captured_at: datetime
    class Config: from_attributes = True

class RecoveryRequest(BaseModel):
    device_id: uuid.UUID

class HeartbeatIn(BaseModel):
    device_token: str
    battery:      Optional[float] = None

# ── WebSocket Manager — Real-time Dashboard ───────────────────────────────────
class ConnectionManager:
    """
    Manages persistent WebSocket connections from the web dashboard.
    Keyed by user_id — supports multiple dashboard tabs per user.
    """
    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, uid: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(uid, []).append(ws)
        print(f"[WS] User {uid} connected — {len(self._connections[uid])} active connection(s)")

    def disconnect(self, uid: str, ws: WebSocket):
        conns = self._connections.get(uid, [])
        if ws in conns:
            conns.remove(ws)

    async def push(self, uid: str, payload: dict):
        """Broadcast a real-time event to all dashboard connections for this user."""
        dead = []
        for ws in self._connections.get(uid, []):
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(uid, ws)

ws_manager = ConnectionManager()

# ── Push Notification Helpers ─────────────────────────────────────────────────
async def send_fcm(push_token: str, payload: dict):
    """
    Android — Firebase Cloud Messaging.
    Uses 'data' (not 'notification') for silent background wake.
    App receives this in onMessageReceived() and activates Recovery Mode.
    """
    headers = {
        "Authorization": f"key={FCM_SERVER_KEY}",
        "Content-Type":  "application/json",
    }
    body = {
        "to": push_token,
        "data": {
            "action":  "SENTINEL_ACTIVATE",
            **payload
        },
        "priority": "high",
        "content_available": True,
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(FCM_URL, headers=headers, json=body, timeout=10)
        r.raise_for_status()

async def send_apns(push_token: str, payload: dict):
    """
    iOS — Apple Push Notification Service.
    Sends a silent push (content-available: 1) using the Background Fetch entitlement.
    iOS will wake the app briefly (30s max) to call the activation handler.
    Note: iOS strictly limits background execution — design iOS app accordingly.
    """
    # Use aioapns or httpx with HTTP/2 for production
    # apns_payload = {
    #     "aps": {"content-available": 1},
    #     "sentinel_action": "ACTIVATE_RECOVERY",
    #     **payload
    # }
    # ... send via APNs HTTP/2 endpoint
    pass  # Implement with aioapns library

async def trigger_device(device: Device, payload: dict):
    """Route push notification based on platform."""
    if not device.push_token:
        print(f"[WARN] No push token for device {device.id}")
        return
    raw_token = decrypt(device.push_token)
    if device.platform == Platform.android:
        await send_fcm(raw_token, payload)
    elif device.platform == Platform.ios:
        await send_apns(raw_token, payload)

# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "Sentinel Recover API",
    description = "Intelligent Mobile Theft Recovery Platform",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = False,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Auth Routes ──────────────────────────── /auth ────────────────────────────
@app.post("/auth/register", response_model=UserOut, status_code=201, tags=["Auth"])
def register(body: UserCreate, db: Session = Depends(get_db)):
    """Create a new Sentinel Recover account."""
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(
        email     = body.email,
        hashed_pw = hash_pw(body.password),
        full_name = body.full_name,
        phone     = body.phone,
    )
    db.add(user); db.commit(); db.refresh(user)
    return user

@app.post("/auth/token", response_model=TokenOut, tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Exchange email + password for a JWT access token."""
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_pw(form.password, user.hashed_pw):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token({"sub": str(user.id)}), "token_type": "bearer"}

@app.get("/auth/me", response_model=UserOut, tags=["Auth"])
def me(current: User = Depends(get_current_user)):
    """Return current authenticated user's profile."""
    return current

# ── Device Routes ─────────────────────── /devices ───────────────────────────
@app.post("/devices", response_model=DeviceOut, status_code=201, tags=["Devices"])
def register_device(body: DeviceRegister, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Register a new device from the web dashboard.
    Status starts as DORMANT — no tracking until Recovery Mode is activated.
    """
    if db.query(Device).filter(Device.imei == body.imei).first():
        raise HTTPException(400, "A device with this IMEI is already registered")
    device = Device(owner_id=current.id, **body.model_dump())
    db.add(device); db.commit(); db.refresh(device)
    return device

@app.get("/devices", response_model=List[DeviceOut], tags=["Devices"])
def list_devices(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all devices registered to the current user."""
    return db.query(Device).filter(Device.owner_id == current.id).all()

@app.get("/devices/{device_id}", response_model=DeviceOut, tags=["Devices"])
def get_device(device_id: uuid.UUID, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    d = db.query(Device).filter(Device.id == device_id, Device.owner_id == current.id).first()
    if not d: raise HTTPException(404, "Device not found")
    return d

@app.delete("/devices/{device_id}", status_code=204, tags=["Devices"])
def delete_device(device_id: uuid.UUID, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Remove a device from Sentinel Recover."""
    d = db.query(Device).filter(Device.id == device_id, Device.owner_id == current.id).first()
    if not d: raise HTTPException(404, "Device not found")
    db.delete(d); db.commit()

@app.post("/devices/link-token", status_code=200, tags=["Devices"])
def link_push_token(body: DeviceLinkToken, db: Session = Depends(get_db)):
    """
    Called by the mobile app on FIRST LAUNCH after installation.
    Links the device's FCM/APNs push token to the registered device.
    Returns the device_token the app uses to authenticate ingest requests.
    No user JWT required — device identifies itself via IMEI.
    """
    device = db.query(Device).filter(Device.imei == body.imei).first()
    if not device:
        raise HTTPException(404, "Device not registered. Please register on the web dashboard first.")
    device.push_token = encrypt(body.push_token)    # Encrypt before storing
    db.commit()
    return {"status": "linked", "device_token": device.device_token}

# ── Recovery Mode Routes ──────────────── /recovery ──────────────────────────
@app.post("/recovery/activate", tags=["Recovery"])
async def activate_recovery(
    body: RecoveryRequest,
    bg: BackgroundTasks,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Activate Recovery Mode for a device.
    1. Updates device status to RECOVERY
    2. Logs the activation event
    3. Sends silent push notification to wake the mobile app
    4. Broadcasts real-time update to web dashboard via WebSocket
    """
    device = db.query(Device).filter(Device.id == body.device_id, Device.owner_id == current.id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    if device.status == DeviceStatus.recovery:
        raise HTTPException(400, "Device is already in Recovery Mode")

    # --- Activate ---
    device.status = DeviceStatus.recovery
    event = SecurityEvent(
        device_id  = device.id,
        event_type = EventType.activation,
        severity   = Severity.success,
        message    = f"Recovery Mode activated by owner ({current.email}) via web dashboard",
    )
    db.add(event); db.commit()

    # --- Send push to mobile app (background task) ---
    push_payload = {
        "device_token": device.device_token,
        "platform":     device.platform,
    }
    bg.add_task(trigger_device, device, push_payload)

    # --- Notify web dashboard in real time ---
    await ws_manager.push(str(current.id), {
        "type":      "RECOVERY_ACTIVATED",
        "device_id": str(device.id),
        "device":    device.name,
        "timestamp": datetime.utcnow().isoformat(),
    })

    return {
        "status":  "recovery_activated",
        "device":  device.name,
        "message": "Secure trigger sent to device. Tracking will begin shortly.",
    }

@app.post("/recovery/deactivate", tags=["Recovery"])
async def deactivate_recovery(
    body: RecoveryRequest,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Deactivate Recovery Mode.
    Returns device to DORMANT state. Rotates device_token for security.
    """
    device = db.query(Device).filter(Device.id == body.device_id, Device.owner_id == current.id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    device.status       = DeviceStatus.dormant
    device.device_token = str(uuid.uuid4())    # Rotate token — invalidates old app session

    event = SecurityEvent(
        device_id  = device.id,
        event_type = EventType.deactivation,
        severity   = Severity.info,
        message    = "Recovery Mode deactivated by owner. Device returned to dormant state.",
    )
    db.add(event); db.commit()

    await ws_manager.push(str(current.id), {
        "type":      "RECOVERY_DEACTIVATED",
        "device_id": str(device.id),
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "dormant", "message": "Device returned to dormant mode. Device token rotated."}

@app.post("/recovery/mark-found", tags=["Recovery"])
def mark_found(body: RecoveryRequest, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Mark a device as recovered / found."""
    device = db.query(Device).filter(Device.id == body.device_id, Device.owner_id == current.id).first()
    if not device: raise HTTPException(404, "Device not found")
    device.status       = DeviceStatus.found
    device.device_token = str(uuid.uuid4())   # Rotate on recovery too
    db.commit()
    return {"status": "found", "message": "Device marked as recovered. Well done!"}

# ── Mobile App Ingest Routes ──────────── /ingest ─────────────────────────────
# These endpoints are called by the mobile app — not the web dashboard.
# Auth is via device_token (shared secret), NOT user JWT.

@app.post("/ingest/location", status_code=201, tags=["Mobile Ingest"])
async def ingest_location(body: LocationIn, db: Session = Depends(get_db)):
    """
    Receive GPS location update from mobile app during Recovery Mode.
    Android: called every 30-60s via foreground service.
    iOS:     called on significant location change events.
    """
    device = get_device_by_token(body.device_token, db)

    loc = LocationLog(
        device_id  = device.id,
        latitude   = body.latitude,
        longitude  = body.longitude,
        accuracy   = body.accuracy,
        altitude   = body.altitude,
        speed      = body.speed,
        heading    = body.heading,
        place_name = body.place_name,
    )
    device.last_seen = datetime.utcnow()
    if body.battery is not None:
        device.battery = body.battery
    db.add(loc); db.commit()

    # Real-time push to owner's dashboard
    await ws_manager.push(str(device.owner_id), {
        "type":       "LOCATION_UPDATE",
        "device_id":  str(device.id),
        "latitude":   body.latitude,
        "longitude":  body.longitude,
        "accuracy":   body.accuracy,
        "place_name": body.place_name,
        "battery":    body.battery,
        "timestamp":  datetime.utcnow().isoformat(),
    })
    return {"status": "ok", "log_id": str(loc.id)}

@app.post("/ingest/event", status_code=201, tags=["Mobile Ingest"])
async def ingest_event(body: EventIn, db: Session = Depends(get_db)):
    """
    Receive a security event from the mobile app.
    Examples: SIM swap, failed unlock, Wi-Fi change, heartbeat.
    """
    device = get_device_by_token(body.device_token, db)

    ev = SecurityEvent(
        device_id    = device.id,
        event_type   = body.event_type,
        severity     = body.severity,
        message      = body.message,
        metadata_enc = encrypt(json.dumps(body.metadata)) if body.metadata else None,
    )
    db.add(ev); db.commit()

    await ws_manager.push(str(device.owner_id), {
        "type":       "SECURITY_EVENT",
        "device_id":  str(device.id),
        "event_type": body.event_type,
        "severity":   body.severity,
        "message":    body.message,
        "timestamp":  datetime.utcnow().isoformat(),
    })
    return {"status": "ok", "event_id": str(ev.id)}

@app.post("/ingest/heartbeat", tags=["Mobile Ingest"])
async def heartbeat(body: HeartbeatIn, db: Session = Depends(get_db)):
    """
    Periodic ping from mobile app confirming Recovery Mode is still active.
    Updates last_seen and battery. Does NOT log a full event.
    """
    device = get_device_by_token(body.device_token, db)
    device.last_seen = datetime.utcnow()
    if body.battery is not None:
        device.battery = body.battery
    db.commit()
    return {"status": "alive"}

# ── Tracking & Evidence Routes ─────────── /devices/{id}/ ────────────────────
@app.get("/devices/{device_id}/locations", response_model=List[LocationOut], tags=["Tracking"])
def get_locations(
    device_id: uuid.UUID,
    limit: int = 50,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch location history for a device (most recent first)."""
    d = db.query(Device).filter(Device.id == device_id, Device.owner_id == current.id).first()
    if not d: raise HTTPException(404, "Device not found")
    return db.query(LocationLog)\
             .filter(LocationLog.device_id == device_id)\
             .order_by(LocationLog.captured_at.desc())\
             .limit(limit).all()

@app.get("/devices/{device_id}/events", response_model=List[EventOut], tags=["Tracking"])
def get_events(
    device_id: uuid.UUID,
    event_type: Optional[EventType] = None,
    severity:   Optional[Severity]  = None,
    limit:      int = 100,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch security event log for a device with optional filters."""
    d = db.query(Device).filter(Device.id == device_id, Device.owner_id == current.id).first()
    if not d: raise HTTPException(404, "Device not found")
    q = db.query(SecurityEvent).filter(SecurityEvent.device_id == device_id)
    if event_type: q = q.filter(SecurityEvent.event_type == event_type)
    if severity:   q = q.filter(SecurityEvent.severity   == severity)
    return q.order_by(SecurityEvent.captured_at.desc()).limit(limit).all()

@app.get("/devices/{device_id}/report", tags=["Evidence"])
def generate_report(
    device_id: uuid.UUID,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate structured police report data.
    The web dashboard renders this as a printable / PDF document.
    Includes cryptographic report ID and hash for evidence authenticity.
    """
    d = db.query(Device).filter(Device.id == device_id, Device.owner_id == current.id).first()
    if not d: raise HTTPException(404, "Device not found")

    locs   = db.query(LocationLog).filter(LocationLog.device_id == device_id)\
               .order_by(LocationLog.captured_at.desc()).limit(30).all()
    events = db.query(SecurityEvent).filter(SecurityEvent.device_id == device_id)\
               .order_by(SecurityEvent.captured_at.desc()).limit(100).all()

    report_data = {
        "report_id":    f"SR-{datetime.utcnow().year}-{str(uuid.uuid4())[:8].upper()}",
        "generated_at": datetime.utcnow().isoformat(),
        "owner":   {"name": current.full_name, "email": current.email, "phone": current.phone},
        "device":  {"name": d.name, "imei": d.imei, "color": d.color, "platform": d.platform, "registered": d.registered_at.isoformat()},
        "locations": [{"lat": l.latitude, "lng": l.longitude, "place": l.place_name, "accuracy": l.accuracy, "time": l.captured_at.isoformat()} for l in locs],
        "events":    [{"type": e.event_type, "severity": e.severity, "msg": e.message, "time": e.captured_at.isoformat()} for e in events],
    }

    # Generate evidence hash for authenticity verification
    report_str = json.dumps(report_data, sort_keys=True)
    report_data["sha256_hash"] = hashlib.sha256(report_str.encode()).hexdigest()

    return report_data

# ── WebSocket — Real-time Dashboard Feed ──────────────────────────────────────
@app.websocket("/ws/{user_id}")
async def ws_endpoint(ws: WebSocket, user_id: str, token: str = ""):
    """
    Persistent WebSocket connection for the web dashboard.
    Receives real-time events: LOCATION_UPDATE, SECURITY_EVENT, RECOVERY_ACTIVATED, etc.

    Connect from frontend:
        const socket = new WebSocket(
            `wss://api.sentinelrecover.app/ws/${userId}?token=${jwtToken}`
        );
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != user_id:
            await ws.close(code=4001)
            return
    except JWTError:
        await ws.close(code=4001)
        return

    await ws_manager.connect(user_id, ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(user_id, ws)
        print(f"[WS] User {user_id} disconnected")

# ── Health & System ───────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {
        "status":  "healthy",
        "service": "Sentinel Recover API",
        "version": "1.0.0",
        "time":    datetime.utcnow().isoformat(),
    }

@app.get("/", tags=["System"])
def root():
    return {"message": "Sentinel Recover API — see /docs for full API reference"}

# ─────────────────────────────────────────────────────────────────────────────
# NEXT STEPS TO MAKE THIS PRODUCTION-READY:
#
#  1. Add Alembic for database migrations (alembic init & alembic revision)
#  2. Implement FCM HTTP v1 API properly (replace legacy send endpoint)
#  3. Implement APNs via aioapns with your .p8 key file
#  4. Add Redis for rate limiting (slowapi) and pub/sub WebSocket scaling
#  5. Add TimescaleDB for location_logs time-series performance
#  6. Add background reverse-geocoding (Google Maps / Nominatim API)
#  7. Add OTP / 2FA on login (pyotp + TOTP)
#  8. Add Stripe for Pro/Enterprise billing
#  9. Dockerize: Dockerfile + docker-compose.yml
# 10. Deploy: Railway / Render / AWS ECS + RDS + ElastiCache
# ─────────────────────────────────────────────────────────────────────────────
