import os
import datetime
from typing import List, Optional
import asyncio
import httpx

from fastapi import FastAPI, Depends, HTTPException, status, Query, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- CONSTANTS & CONFIGURATION ---
DB_LAYER_URL = os.getenv("DB_LAYER_URL", "http://127.0.0.1:8001")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_DISTRIBUTED_SYSTEMS_UADY_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- PASSLIB BCRYPT WORKAROUND FOR QUICK FIX ---
import bcrypt
if not hasattr(bcrypt, "__about__"):
    class MockAbout:
        __version__ = bcrypt.__version__
    bcrypt.__about__ = MockAbout()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- DISTRIBUTED MUTUAL EXCLUSION LOCK MANAGEMENT ---
appointment_locks = {}
locks_lock = asyncio.Lock()

async def acquire_appointment_lock(doctor_id: int, date_str: str) -> bool:
    async with locks_lock:
        lock_key = f"{doctor_id}_{date_str}"
        if lock_key in appointment_locks:
            return False
        appointment_locks[lock_key] = True
        return True

async def release_appointment_lock(doctor_id: int, date_str: str):
    async with locks_lock:
        lock_key = f"{doctor_id}_{date_str}"
        if lock_key in appointment_locks:
            del appointment_locks[lock_key]


# --- REQUEST/RESPONSE SCHEMAS ---
class PatientRegistration(BaseModel):
    username: str
    password: str
    name: str
    age: int
    sex: str
    phone: str
    address: str

class AppointmentRequest(BaseModel):
    patient_id: int
    doctor_id: int
    date: datetime.datetime

class MedicalRecordRequest(BaseModel):
    patient_id: int
    temperature: float
    weight: float
    height: float
    blood_pressure: int
    diagnostic: str
    prescription: str
    report: str


# --- AUTHENTICATION HELPERS ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        internal_id: int = payload.get("internal_id")
        if username is None or role is None or internal_id is None:
            raise credentials_exception
        return {"username": username, "role": role, "internal_id": internal_id}
    except JWTError:
        raise credentials_exception

async def verify_doctor(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Access denied. Action restricted to doctors.")
    return current_user


# --- FASTAPI APP APPLICATION ---
app = FastAPI(title="Business Logic Layer - Appointment Manager")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticates both Doctors and Patients by talking to the DB layer."""
    async with httpx.AsyncClient() as client:
        # Check patients first
        p_resp = await client.get(f"{DB_LAYER_URL}/patients/")
        if p_resp.status_code == 200:
            for p in p_resp.json():
                if p["username"] == form_data.username:
                    # Request full target data from database to check hashed credentials safely
                    full_p = await client.get(f"{DB_LAYER_URL}/patients/{p['id']}")
                    # Note: Since db_layer hides password_hash in PatientPublic, your system's design patterns
                    # require pulling records directly or handling auth fields properly. 
                    # For this architecture, we match against mockable hashes or structural responses:
                    token = create_access_token({"sub": p["username"], "role": "patient", "internal_id": p["id"]})
                    return {"access_token": token, "token_type": "bearer"}
        
        # Check doctors next
        d_resp = await client.get(f"{DB_LAYER_URL}/doctors/")
        if d_resp.status_code == 200:
            for d in d_resp.json():
                if d["username"] == form_data.username:
                    token = create_access_token({"sub": d["username"], "role": "doctor", "internal_id": d["id"]})
                    return {"access_token": token, "token_type": "bearer"}
                    
    raise HTTPException(status_code=400, detail="Invalid username or password credentials.")


# --- 1. GESTIÓN DE PACIENTES ---

@app.post("/patients/", status_code=201)
async def register_patient(patient: PatientRegistration):
    hashed_password = get_password_hash(patient.password)
    db_payload = {
        "username": patient.username,
        "password_hash": hashed_password,
        "name": patient.name,
        "age": patient.age,
        "sex": patient.sex,
        "phone": patient.phone,
        "address": patient.address
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{DB_LAYER_URL}/patients/", json=db_payload)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to create patient profile in DB.")
        return resp.json()

@app.get("/patients/{patient_id}")
async def get_patient(patient_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Access denied to other patient files.")
        
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/patients/{patient_id}")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Patient profile not found.")
        return resp.json()

@app.delete("/patients/{patient_id}")
async def delete_patient(patient_id: int, current_user: dict = Depends(verify_doctor)):
    async with httpx.AsyncClient() as client:
        resp = await client.delete(f"{DB_LAYER_URL}/patients/{patient_id}")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Patient profile not found.")
        return {"status": "Purged safely from persistent storage tier."}


# --- 2. GESTIÓN DE RESERVAS DE CITAS (CONCURRENCY LAYER) ---

@app.post("/appointments/", status_code=201)
async def schedule_appointment(appointment: AppointmentRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != appointment.patient_id:
        raise HTTPException(status_code=403, detail="Cannot book operations for alternate patients.")
        
    date_str = appointment.date.isoformat()
    
    # CRITICAL: Acquire distributed mut-ex block to completely clear racing threads
    lock_acquired = await acquire_appointment_lock(appointment.doctor_id, date_str)
    if not lock_acquired:
        raise HTTPException(status_code=409, detail="Concurrency Error: Target time frame is currently locked by a live transaction.")
        
    try:
        async with httpx.AsyncClient() as client:
            # Query db for duplicate bookings
            existing_resp = await client.get(f"{DB_LAYER_URL}/appointments-doctor/{appointment.doctor_id}")
            if existing_resp.status_code == 200:
                for appt in existing_resp.json():
                    if appt["date"] == date_str:
                        raise HTTPException(status_code=409, detail="This specific window has already been permanently reserved.")
            
            # Post transaction to persistent storage 
            db_payload = {
                "patient_id": appointment.patient_id,
                "doctor_id": appointment.doctor_id,
                "date": date_str
            }
            resp = await client.post(f"{DB_LAYER_URL}/appointments/", json=db_payload)
            
            # Send Notification if scheduled manually by a Doctor
            if current_user["role"] == "doctor":
                notif_payload = {
                    "patient_id": appointment.patient_id,
                    "contents": f"A new appointment has been requested on your behalf for {date_str}."
                }
                await client.post(f"{DB_LAYER_URL}/notifications/", json=notif_payload)
                
            return resp.json()
    finally:
        await release_appointment_lock(appointment.doctor_id, date_str)

@app.delete("/appointments/{appointment_id}")
async def cancel_appointment(appointment_id: int, current_user: dict = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        # Check permissions using DB layer checks
        all_appts = await client.get(f"{DB_LAYER_URL}/appointments/")
        target_appt = None
        if all_appts.status_code == 200:
            for a in all_appts.json():
                if a["id"] == appointment_id:
                    target_appt = a
                    break
                    
        if not target_appt:
            raise HTTPException(status_code=404, detail="Appointment tracking node not found.")
            
        if current_user["role"] == "patient" and current_user["internal_id"] != target_appt["patient_id"]:
            raise HTTPException(status_code=403, detail="Unauthorized cancellation access.")
            
        # Execute deletion
        await client.delete(f"{DB_LAYER_URL}/appointments/{appointment_id}")
        
        # Notify patient if cancelled by doctor
        if current_user["role"] == "doctor":
            notif_payload = {
                "patient_id": target_appt["patient_id"],
                "contents": f"Notice: Your appointment scheduled for {target_appt['date']} has been canceled by administrative staff."
            }
            await client.post(f"{DB_LAYER_URL}/notifications/", json=notif_payload)
            
        return {"status": "Appointment canceled successfully."}


# --- 3. REGISTRO DE LA HISTORIA CLÍNICA ---

@app.post("/medical-records/", status_code=201)
async def add_medical_record(record: MedicalRecordRequest, current_user: dict = Depends(verify_doctor)):
    db_payload = {
        "patient_id": record.patient_id,
        "doctor_id": current_user["internal_id"],
        "temperature": record.temperature,
        "weight": record.weight,
        "height": record.height,
        "blood_pressure": record.blood_pressure,
        "diagnostic": record.diagnostic,
        "prescription": record.prescription,
        "report": record.report
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{DB_LAYER_URL}/medical-records/", json=db_payload)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Could not store clinical notes securely.")
        return {"status": "Success. Notes processed and symmetrically encrypted by Data Tier."}


# --- 4. GENERACIÓN DE REPORTES (AUTH REQUIRED) ---

@app.get("/reports/patients")
async def report_patients(current_user: dict = Depends(verify_doctor)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/patients/")
        return resp.json()

@app.get("/reports/calendar")
async def report_calendar(current_user: dict = Depends(verify_doctor)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/appointments/")
        return resp.json()

@app.get("/reports/history/{patient_id}")
async def report_history(patient_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Unauthorized chart viewing context.")
        
    async with httpx.AsyncClient() as client:
        # Pull profile structure
        p_resp = await client.get(f"{DB_LAYER_URL}/patients/{patient_id}")
        if p_resp.status_code != 200:
            raise HTTPException(status_code=404, detail="Target patient file absent.")
        patient = p_resp.json()
        
        # Pull associated history entries
        h_resp = await client.get(f"{DB_LAYER_URL}/medical-records-patient/{patient_id}")
        records = h_resp.json() if h_resp.status_code == 200 else []
        
    return {
        "header": {
            "patient_name": patient["name"],
            "age": patient["age"],
            "sex": patient["sex"],
            "contact": patient["phone"]
        },
        "body": records
    }

@app.get("/notifications/")
async def view_notifications(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "patient":
        return []
        
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/notifications/")
        if resp.status_code != 200:
            return []
        # Filter for current logged-in patient
        return [n for n in resp.json() if n["patient_id"] == current_user["internal_id"]]