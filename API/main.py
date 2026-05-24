import os
import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import asyncio

# --- CRYPTOGRAPHY & SECURITY CONFIG ---
# In a production environment, keep these in your environment variables.
SECRET_KEY = "5fdb6feb52e573c3df8a030c3ef2aa7d7a14acc8243e168c01e3e5e83ba3a1df"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Symmetric encryption key for Medical Records (Requirement: Stored Encrypted)
# Generating a stable key for demonstration purposes
FERNET_KEY = Fernet.generate_key() 
cipher_suite = Fernet(FERNET_KEY)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- CONCURRENCY CONTROL (DISTRIBUTED MUTUAL EXCLUSION MOCK) ---
# To prevent race conditions on matching appointment slots (Doctor + DateTime)
appointment_locks = {}
locks_lock = asyncio.Lock()

async def acquire_appointment_lock(doctor_id: int, date_str: str) -> bool:
    """Simulates acquiring a distributed lock for a specific slot."""
    async with locks_lock:
        lock_key = f"{doctor_id}_{date_str}"
        if lock_key in appointment_locks:
            return False
        appointment_locks[lock_key] = True
        return True

async def release_appointment_lock(doctor_id: int, date_str: str):
    """Releases the lock for a slot."""
    async with locks_lock:
        lock_key = f"{doctor_id}_{date_str}"
        if lock_key in appointment_locks:
            del appointment_locks[lock_key]

# --- PASSTHROUGH IN-MEMORY DATA LAYER SIMULATION ---
# This mirrors your provided data layer functions to make this file completely executable.
# In production, replace these mocks with imports from your actual database layer file.

class MockDB:
    patients = {}
    doctors = {}
    appointments = {}
    notifications = {}
    medical_records = {}
    users = {} # username -> password_hash, role, internal_id
    patient_id_counter = 1
    doctor_id_counter = 1
    appointment_id_counter = 1
    notification_id_counter = 1
    record_id_counter = 1

# Pre-populate a sample Doctor for testing
MockDB.doctors[1] = {"id": 1, "username": "dr_smith", "name": "Dr. Smith"}
MockDB.users["dr_smith"] = {
    "username": "dr_smith", 
    "password_hash": pwd_context.hash("uady2026"), 
    "role": "doctor", 
    "internal_id": 1
}

# --- HELPER UTILITIES ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def encrypt_data(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    return cipher_suite.decrypt(token.encode()).decode()

# --- DEPENDENCIES ---
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
        if username is None or role is None:
            raise credentials_exception
        return {"username": username, "role": role, "internal_id": internal_id}
    except JWTError:
        raise credentials_exception

async def verify_doctor(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Operation restricted to Doctors only.")
    return current_user

# --- FASTAPI INITIALIZATION ---
app = FastAPI(title="Distributed Medical Appointment System - UADY 2026")

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = MockDB.users.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"], "internal_id": user["internal_id"]}
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- 1. PATIENT MANAGEMENT ENDPOINTS ---

@app.post("/patients/", status_code=201)
async def register_patient(patient_data: dict):
    # patient_data keys: username, password, name, age, sex, phone, address
    if patient_data["username"] in MockDB.users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    p_id = MockDB.patient_id_counter
    MockDB.patient_id_counter += 1
    
    hashed_pw = get_password_hash(patient_data["password"])
    
    # Save to user auth directory
    MockDB.users[patient_data["username"]] = {
        "username": patient_data["username"],
        "password_hash": hashed_pw,
        "role": "patient",
        "internal_id": p_id
    }
    
    # Save to patient profile directory
    new_patient = {
        "id": p_id,
        "username": patient_data["username"],
        "name": patient_data["name"],
        "age": patient_data["age"],
        "sex": patient_data["sex"],
        "phone": patient_data["phone"],
        "address": patient_data["address"]
    }
    MockDB.patients[p_id] = new_patient
    return new_patient

@app.get("/patients/{patient_id}")
async def get_patient_profile(patient_id: int, current_user: dict = Depends(get_current_user)):
    # Security Rule: Patients can only see themselves; Doctors can see anyone
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Access denied to this profile.")
    
    patient = MockDB.patients.get(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

@app.put("/patients/{patient_id}")
async def update_patient_profile(patient_id: int, update_data: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Access denied.")
    
    patient = MockDB.patients.get(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    for key, value in update_data.items():
        if key in patient:
            patient[key] = value
            
    return {"message": "Patient profile updated successfully", "patient": patient}

@app.delete("/patients/{patient_id}")
async def remove_patient(patient_id: int, current_user: dict = Depends(verify_doctor)):
    patient = MockDB.patients.get(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Delete credentials and profile record
    username = patient["username"]
    if username in MockDB.users:
        del MockDB.users[username]
    del MockDB.patients[patient_id]
    return {"message": "Patient records purged successfully"}


# --- 2. APPOINTMENT SCHEDULING & MUTUAL EXCLUSION ---

@app.post("/appointments/", status_code=201)
async def schedule_appointment(appointment: dict, current_user: dict = Depends(get_current_user)):
    # appointment keys: patient_id, doctor_id, date (e.g., "2026-05-26 10:00")
    p_id = appointment["patient_id"]
    d_id = appointment["doctor_id"]
    date_str = appointment["date"]
    
    # Enforce standard scoping rules
    if current_user["role"] == "patient" and current_user["internal_id"] != p_id:
        raise HTTPException(status_code=403, detail="Cannot book appointments for other patients.")
        
    # CONCURRENCY GUARD: Acquire mutual exclusion lock over slot string
    lock_acquired = await acquire_appointment_lock(d_id, date_str)
    if not lock_acquired:
        raise HTTPException(
            status_code=409, 
            detail="Concurrency Conflict: This time slot has already been locked or booked by another transaction."
        )
        
    try:
        # Check database for existing conflicts
        for appt in MockDB.appointments.values():
            if appt["doctor_id"] == d_id and appt["date"] == date_str:
                raise HTTPException(status_code=409, detail="This scheduling window is completely booked.")
        
        # Safe to save
        appt_id = MockDB.appointment_id_counter
        MockDB.appointment_id_counter += 1
        
        new_appt = {
            "id": appt_id,
            "patient_id": p_id,
            "doctor_id": d_id,
            "date": date_str
        }
        MockDB.appointments[appt_id] = new_appt
        
        # Notification service fallback if booked by a doctor
        if current_user["role"] == "doctor":
            notif_id = MockDB.notification_id_counter
            MockDB.notification_id_counter += 1
            MockDB.notifications[notif_id] = {
                "id": notif_id,
                "patient_id": p_id,
                "contents": f"Your doctor has registered a new appointment for you on {date_str}.",
                "read": False
            }
            
        return new_appt
    finally:
        # Always release the resource lock
        await release_appointment_lock(d_id, date_str)

@app.delete("/appointments/{appointment_id}")
async def cancel_appointment(appointment_id: int, current_user: dict = Depends(get_current_user)):
    appt = MockDB.appointments.get(appointment_id)
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment slot does not exist.")
        
    if current_user["role"] == "patient" and current_user["internal_id"] != appt["patient_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized cancellation attempt.")
        
    # Send notice if actioned by a Doctor
    if current_user["role"] == "doctor":
        notif_id = MockDB.notification_id_counter
        MockDB.notification_id_counter += 1
        MockDB.notifications[notif_id] = {
            "id": notif_id,
            "patient_id": appt["patient_id"],
            "contents": f"ALERT: Your appointment scheduled for {appt['date']} has been cancelled by the medical staff.",
            "read": False
        }
        
    del MockDB.appointments[appointment_id]
    return {"message": "Appointment cancelled successfully."}


# --- 3. MEDICAL RECORD MANAGEMENT (WITH FERNET ENCRYPTION) ---

@app.post("/medical-records/", status_code=201)
async def create_medical_record(record_data: dict, current_user: dict = Depends(verify_doctor)):
    # record_data keys: patient_id, temperature, weight, height, blood_pressure, diagnostic, prescription, report
    r_id = MockDB.record_id_counter
    MockDB.record_id_counter += 1
    
    # Data is securely encrypted before hand-off to the Data Persistance Tier
    encrypted_payload = {
        "id": r_id,
        "patient_id": record_data["patient_id"],
        "doctor_id": current_user["internal_id"],
        "date": datetime.date.today().isoformat(),
        "temperature": encrypt_data(str(record_data["temperature"])),
        "weight": encrypt_data(str(record_data["weight"])),
        "height": encrypt_data(str(record_data["height"])),
        "blood_pressure": encrypt_data(record_data["blood_pressure"]),
        "diagnostic": encrypt_data(record_data["diagnostic"]),
        "prescription": encrypt_data(record_data["prescription"]),
        "report": encrypt_data(record_data["report"])
    }
    
    MockDB.medical_records[r_id] = encrypted_payload
    return {"message": "Medical record filed securely under encrypted status.", "record_id": r_id}


# --- 4. REPORT GENERATION TIERS ---

@app.get("/reports/patients")
async def list_patients_report(current_user: dict = Depends(verify_doctor)):
    return list(MockDB.patients.values())

@app.get("/reports/calendar")
async def view_calendar_report(current_user: dict = Depends(verify_doctor)):
    return list(MockDB.appointments.values())

@app.get("/reports/history/{patient_id}")
async def clinical_history_report(patient_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Unauthorized visibility access.")
        
    patient = MockDB.patients.get(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient profile missing.")
        
    # Gather and transparently decrypt all matching consultations
    decrypted_history = []
    for record in MockDB.medical_records.values():
        if record["patient_id"] == patient_id:
            decrypted_history.append({
                "date": record["date"],
                "doctor_id": record["doctor_id"],
                "vitals": {
                    "temperature": decrypt_data(record["temperature"]),
                    "weight": decrypt_data(record["weight"]),
                    "height": decrypt_data(record["height"]),
                    "blood_pressure": decrypt_data(record["blood_pressure"])
                },
                "clinical_notes": {
                    "diagnostic": decrypt_data(record["diagnostic"]),
                    "prescription": decrypt_data(record["prescription"]),
                    "report": decrypt_data(record["report"])
                }
            })
            
    return {
        "header": {
            "patient_name": patient["name"],
            "age": patient["age"],
            "sex": patient["sex"],
            "contact": patient["phone"]
        },
        "body": decrypted_history
    }

@app.get("/notifications/")
async def fetch_notifications(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "patient":
        return []
    
    p_id = current_user["internal_id"]
    return [n for n in MockDB.notifications.values() if n["patient_id"] == p_id]