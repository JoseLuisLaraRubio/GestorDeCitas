import os
import datetime
import sqlite3
from pathlib import Path
from typing import Optional
import httpx

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from pwdlib import PasswordHash

# Config
DB_LAYER_URL = os.getenv("DB_LAYER_URL", "http://127.0.0.1:8001")
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE_PATH = REPO_ROOT / "database.db"
DB_SQLITE_PATH = Path(os.getenv("DB_SQLITE_PATH", str(DEFAULT_SQLITE_PATH)))
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_DISTRIBUTED_SYSTEMS_UADY_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

AUTH_ENDPOINT_BY_ROLE = {"patient": "patients-auth", "doctor": "doctors-auth"}
AUTH_TABLE_BY_ROLE = {"patient": "patient", "doctor": "doctor"}

password_hash_helper = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class PatientRegistration(BaseModel):
    username: str
    password: str
    name: str
    age: int
    sex: str
    phone: str
    address: str

class PatientUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    name: Optional[str] = None
    age: Optional[int] = None
    sex: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None

class AppointmentRequest(BaseModel):
    patient_id: int
    doctor_id: int
    date: datetime.datetime

class AppointmentUpdate(BaseModel):
    doctor_id: Optional[int] = None
    date: Optional[datetime.datetime] = None

class MedicalRecordRequest(BaseModel):
    patient_id: int
    temperature: float
    weight: float
    height: float
    blood_pressure: int
    diagnostic: str
    prescription: str
    report: str


# Helpers
def verify_password(plain_password, hashed_password):
    return password_hash_helper.verify(plain_password, hashed_password)

def get_password_hash(password):
    return password_hash_helper.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def _sqlite_lookup_user(table: str, username: str) -> Optional[dict]:
    if not DB_SQLITE_PATH.exists():
        return None
    connection = sqlite3.connect(DB_SQLITE_PATH)
    try:
        cursor = connection.execute(
            f"SELECT id, username, password_hash FROM {table} WHERE username = ? LIMIT 1",
            (username,),
        )
        row = cursor.fetchone()
    finally:
        connection.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "password_hash": row[2]}

async def _fetch_auth_record(role: str, username: str) -> Optional[dict]:
    endpoint = AUTH_ENDPOINT_BY_ROLE[role]
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{DB_LAYER_URL}/{endpoint}/{username}")
    except httpx.RequestError:
        resp = None

    if resp is not None:
        if resp.status_code == 200:
            payload = resp.json()
            if "password_hash" in payload and "id" in payload:
                return payload
        if resp.status_code not in (404, 405):
            raise HTTPException(status_code=resp.status_code, detail="Failed to read user credentials.")

    table = AUTH_TABLE_BY_ROLE[role]
    return _sqlite_lookup_user(table, username)

def ensure_valid_appointment_time(target: datetime.datetime):
    if target.minute != 0 or target.second != 0 or target.microsecond != 0:
        raise HTTPException(status_code=400, detail="Appointments must start on the hour.")
    if target.hour < 9 or target.hour >= 19:
        raise HTTPException(status_code=400, detail="Appointments must start between 09:00 and 18:00.")

def _normalize_datetime(value) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        normalized = value
    else:
        try:
            normalized = datetime.datetime.fromisoformat(value)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid appointment date format.")
    if normalized.tzinfo is not None:
        normalized = normalized.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return normalized

async def _find_appointment_in_list(
    client: httpx.AsyncClient, url: str, appointment_id: int
) -> Optional[dict]:
    resp = await client.get(url)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail="Failed to read appointments.")
    for appointment in resp.json():
        if appointment.get("id") == appointment_id:
            return appointment
    return None

async def ensure_appointment_slot_available(
    doctor_id: int, target_date: datetime.datetime, exclude_id: Optional[int] = None
) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/appointments-doctor/{doctor_id}")
        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail="Failed to validate appointment availability.",
            )
        target = _normalize_datetime(target_date)
        for appointment in resp.json():
            if appointment.get("id") == exclude_id:
                continue
            if _normalize_datetime(appointment.get("date")) == target:
                raise HTTPException(
                    status_code=409,
                    detail="This specific window has already been reserved.",
                )

async def fetch_appointment_or_404(
    appointment_id: int, current_user: Optional[dict] = None
) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/appointments/{appointment_id}")
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code not in (404, 405):
            raise HTTPException(status_code=resp.status_code, detail="Failed to read appointment.")

        appointment = await _find_appointment_in_list(
            client, f"{DB_LAYER_URL}/appointments/", appointment_id
        )
        if appointment is not None:
            return appointment

        if current_user:
            if current_user["role"] == "patient":
                appointment = await _find_appointment_in_list(
                    client,
                    f"{DB_LAYER_URL}/appointments-patient/{current_user['internal_id']}",
                    appointment_id,
                )
            elif current_user["role"] == "doctor":
                appointment = await _find_appointment_in_list(
                    client,
                    f"{DB_LAYER_URL}/appointments-doctor/{current_user['internal_id']}",
                    appointment_id,
                )
            if appointment is not None:
                return appointment

        raise HTTPException(status_code=404, detail="Appointment not found.")

async def ensure_patient_exists(patient_id: int) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/patients/{patient_id}")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Patient profile not found.")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to verify patient.")

async def ensure_doctor_exists(doctor_id: int) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/doctors/{doctor_id}")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Doctor profile not found.")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to verify doctor.")

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


# App 
app = FastAPI(title="Business Logic Layer - Appointment Manager (Pwdlib Migration)")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticates both Doctors and Patients securely via pwdlib."""
    patient = await _fetch_auth_record("patient", form_data.username)
    if patient:
        try:
            if verify_password(form_data.password, patient["password_hash"]):
                token = create_access_token({
                    "sub": patient["username"],
                    "role": "patient",
                    "internal_id": patient["id"],
                })
                return {"access_token": token, "token_type": "bearer"}
        except Exception:
            pass

    doctor = await _fetch_auth_record("doctor", form_data.username)
    if doctor:
        try:
            if verify_password(form_data.password, doctor["password_hash"]):
                token = create_access_token({
                    "sub": doctor["username"],
                    "role": "doctor",
                    "internal_id": doctor["id"],
                })
                return {"access_token": token, "token_type": "bearer"}
        except Exception:
            pass
                    
    raise HTTPException(status_code=400, detail="Invalid username or password credentials.")


# Patients
@app.post("/patients/", status_code=201)
async def register_patient(patient: PatientRegistration):
    # This now utilizes pwdlib cleanly, resolving the 72-byte value errors completely!
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

@app.get("/patients/")
async def list_patients(current_user: dict = Depends(verify_doctor)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/patients/")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to read patients.")
        return resp.json()

@app.patch("/patients/{patient_id}")
async def update_patient(
    patient_id: int,
    patient: PatientUpdate,
    current_user: dict = Depends(get_current_user),
):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Access denied to other patient files.")

    payload = patient.model_dump(exclude_unset=True)
    if "password" in payload:
        payload["password_hash"] = get_password_hash(payload.pop("password"))

    async with httpx.AsyncClient() as client:
        resp = await client.patch(f"{DB_LAYER_URL}/patients/{patient_id}", json=payload)
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Patient profile not found.")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to update patient profile.")
        return resp.json()

@app.delete("/patients/{patient_id}")
async def delete_patient(patient_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Access denied to other patient files.")
    async with httpx.AsyncClient() as client:
        resp = await client.delete(f"{DB_LAYER_URL}/patients/{patient_id}")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Patient profile not found.")
        return {"status": "Purged safely from persistent storage tier."}
# End Patients

# Appointments
@app.post("/appointments/", status_code=201)
async def schedule_appointment(appointment: AppointmentRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != appointment.patient_id:
        raise HTTPException(status_code=403, detail="Cannot book operations for alternate patients.")
    
    ensure_valid_appointment_time(appointment.date)
    await ensure_patient_exists(appointment.patient_id)
    await ensure_doctor_exists(appointment.doctor_id)
    await ensure_appointment_slot_available(appointment.doctor_id, appointment.date)
    date_str = appointment.date.isoformat()

    async with httpx.AsyncClient() as client:
        db_payload = {
            "patient_id": appointment.patient_id,
            "doctor_id": appointment.doctor_id,
            "date": date_str
        }
        resp = await client.post(f"{DB_LAYER_URL}/appointments/", json=db_payload)
        if resp.status_code == 409:
            raise HTTPException(status_code=409, detail="This specific window has already been reserved.")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to schedule appointment.")

        if current_user["role"] == "doctor":
            notif_payload = {
                "patient_id": appointment.patient_id,
                "contents": f"A new appointment has been requested on your behalf for {date_str}."
            }
            await client.post(f"{DB_LAYER_URL}/notifications/", json=notif_payload)
            
        return resp.json()

@app.get("/appointments/{appointment_id}")
async def get_appointment(appointment_id: int, current_user: dict = Depends(get_current_user)):
    appointment = await fetch_appointment_or_404(appointment_id, current_user)
    if current_user["role"] == "patient" and current_user["internal_id"] != appointment["patient_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized appointment access.")
    return appointment

@app.get("/appointments/patient/{patient_id}")
async def list_patient_appointments(patient_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "patient" and current_user["internal_id"] != patient_id:
        raise HTTPException(status_code=403, detail="Unauthorized appointment access.")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/appointments-patient/{patient_id}")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to read appointments.")
        return resp.json()

@app.get("/appointments/doctor/{doctor_id}")
async def list_doctor_appointments(doctor_id: int, current_user: dict = Depends(verify_doctor)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{DB_LAYER_URL}/appointments-doctor/{doctor_id}")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to read appointments.")
        return resp.json()

@app.patch("/appointments/{appointment_id}")
async def update_appointment(
    appointment_id: int,
    appointment: AppointmentUpdate,
    current_user: dict = Depends(get_current_user),
):
    current = await fetch_appointment_or_404(appointment_id, current_user)
    if current_user["role"] == "patient" and current_user["internal_id"] != current["patient_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized appointment access.")

    payload = appointment.model_dump(exclude_unset=True)
    if current_user["role"] == "patient" and "doctor_id" in payload:
        raise HTTPException(status_code=403, detail="Patients cannot change doctor assignment.")

    target_date = None
    if "date" in payload:
        if appointment.date is None:
            raise HTTPException(status_code=400, detail="Appointment date is required.")
        ensure_valid_appointment_time(appointment.date)
        target_date = appointment.date
        payload["date"] = appointment.date.isoformat()
    if "doctor_id" in payload and payload["doctor_id"] is not None:
        await ensure_doctor_exists(payload["doctor_id"])

    if "date" in payload or "doctor_id" in payload:
        resolved_date = target_date or _normalize_datetime(current["date"])
        resolved_doctor = payload.get("doctor_id", current["doctor_id"])
        await ensure_appointment_slot_available(
            resolved_doctor,
            resolved_date,
            exclude_id=appointment_id,
        )

    async with httpx.AsyncClient() as client:
        resp = await client.patch(f"{DB_LAYER_URL}/appointments/{appointment_id}", json=payload)
        if resp.status_code == 409:
            raise HTTPException(status_code=409, detail="This specific window has already been reserved.")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Appointment not found.")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Failed to update appointment.")

        if current_user["role"] == "doctor" and "date" in payload:
            notif_payload = {
                "patient_id": current["patient_id"],
                "contents": f"Your appointment has been updated to {payload['date']}."
            }
            await client.post(f"{DB_LAYER_URL}/notifications/", json=notif_payload)
        return resp.json()

@app.delete("/appointments/{appointment_id}")
async def cancel_appointment(appointment_id: int, current_user: dict = Depends(get_current_user)):
    target_appt = await fetch_appointment_or_404(appointment_id, current_user)
    if current_user["role"] == "patient" and current_user["internal_id"] != target_appt["patient_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized cancellation access.")

    async with httpx.AsyncClient() as client:
        await client.delete(f"{DB_LAYER_URL}/appointments/{appointment_id}")

        if current_user["role"] == "doctor":
            notif_payload = {
                "patient_id": target_appt["patient_id"],
                "contents": f"Notice: Your appointment scheduled for {target_appt['date']} has been canceled."
            }
            await client.post(f"{DB_LAYER_URL}/notifications/", json=notif_payload)

        return {"status": "Appointment canceled successfully."}
# End Appointments

# Medical Records
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
        return {"status": "Success. Notes stored securely."}
# End Medical Records

# Reports and notifications
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
        p_resp = await client.get(f"{DB_LAYER_URL}/patients/{patient_id}")
        if p_resp.status_code != 200:
            raise HTTPException(status_code=404, detail="Target patient file absent.")
        patient = p_resp.json()
        
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
        return [n for n in resp.json() if n["patient_id"] == current_user["internal_id"]]

# End Reports and notifications