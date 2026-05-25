import os
from dotenv import load_dotenv
from typing import Annotated

from datetime import datetime
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlalchemy import LargeBinary, TypeDecorator, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from cryptography.fernet import Fernet

# Encryption
load_dotenv()

FERNET_KEY = str(os.getenv("FERNET_KEY"))
cipher_suite = Fernet(FERNET_KEY.encode())

class Encrypted(TypeDecorator):
    impl = LargeBinary
    cache_ok = True

    def __init__(self, target_type):
        super().__init__()
        self.target_type = target_type

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return cipher_suite.encrypt(str(value).encode())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        decrypted = cipher_suite.decrypt(value).decode()
        return self.target_type(decrypted)
# End Encryption

# Models
class User(SQLModel):
    username : str = Field(index=True)
    password_hash : str = Field(index=True)
    name: str = Field(index=True)

class Patient(User, table=True):
    id: int | None = Field(default=None, primary_key=True)
    age: int
    sex: str
    phone: str
    address: str

class PatientCreate(User):
    age: int
    sex: str
    phone: str
    address: str

class PatientPublic(SQLModel):
    id: int
    username: str
    name: str
    age: int
    sex: str
    phone: str
    address: str

class PatientUpdate(SQLModel):
    username: str | None = None
    password_hash: str | None = None
    name: str | None = None
    age: int | None = None
    sex: str | None = None
    phone: str | None = None
    address: str | None = None

class Doctor(User, table=True):
    id: int | None = Field(default=None, primary_key=True)

class DoctorCreate(User):
    pass

class DoctorPublic(SQLModel):
    id: int
    username: str
    name: str

class DoctorUpdate(SQLModel):
    username: str | None = None
    password_hash: str | None = None
    name: str | None = None

class Appointment(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("doctor_id", "date"),
    )
    id: int | None = Field(default=None, primary_key=True)
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    doctor_id: int | None = Field(default=None, foreign_key="doctor.id")
    date: datetime

class AppointmentCreate(SQLModel):
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    doctor_id: int | None = Field(default=None, foreign_key="doctor.id")
    date: datetime

class AppointmentUpdate(SQLModel):
    doctor_id: int | None = Field(default=None, foreign_key="doctor.id")
    date: datetime  | None = None

class Notification(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    contents: str
    read: bool = Field(default=False, index=True)

class NotificationCreate(SQLModel):
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    contents: str

class NotificationUpdate(SQLModel):
    contents: str | None = None
    read: bool | None = None

class MedicalRecordBase(SQLModel):
    temperature: float = Field(sa_type=Encrypted(float))
    weight: float = Field(sa_type=Encrypted(float))
    height: float = Field(sa_type=Encrypted(float))
    blood_pressure: int = Field(sa_type=Encrypted(int))
    diagnostic: str = Field(sa_type=Encrypted(str))
    prescription: str = Field(sa_type=Encrypted(str))
    report: str = Field(sa_type=Encrypted(str))

class MedicalRecord(MedicalRecordBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    doctor_id: int | None = Field(default=None, foreign_key="doctor.id")
    date: datetime = Field(default_factory=datetime.now)

class MedicalRecordCreate(MedicalRecordBase):
    patient_id: int | None = Field(default=None, foreign_key="patient.id")
    doctor_id: int | None = Field(default=None, foreign_key="doctor.id")

class MedicalRecordUpdate(MedicalRecordBase):
    temperature: float | None = Field(default=None, sa_type=Encrypted(float))
    weight: float | None = Field(default=None, sa_type=Encrypted(float))
    height: float | None = Field(default=None, sa_type=Encrypted(float))
    blood_pressure: int | None = Field(default=None, sa_type=Encrypted(int))
    diagnostic: str | None = Field(default=None, sa_type=Encrypted(str))
    prescription: str | None = Field(default=None, sa_type=Encrypted(str))
    report: str | None = Field(default=None, sa_type=Encrypted(str))
# End Models

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]
app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()


# Appointments
@app.get("/appointments/", response_model=list[Appointment])
def read_all_appointments(session: SessionDep, limit:Annotated[int, Query(le=100)] = 100):
    now = datetime.now()
    statement = (
        select(Appointment)
        .where(Appointment.date >= now)
        .order_by(Appointment.date)
        .limit(limit)
    )
    appointments = session.exec(statement).all()
    return appointments

@app.get("/appointments-patient/{patient_id}", response_model=list[Appointment])
def read_patient_appointments(
    patient_id: int,
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    statement = (
        select(Appointment)
        .where(Appointment.patient_id == patient_id)
        .order_by(Appointment.date)
        .offset(offset)
        .limit(limit)
    )
    appointments = session.exec(statement).all()
    return appointments

@app.get("/appointments-doctor/{doctor_id}", response_model=list[Appointment])
def read_doctor_appointment(
    doctor_id: int,
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    statement = (
        select(Appointment)
        .where(Appointment.doctor_id == doctor_id)
        .order_by(Appointment.date)
        .offset(offset)
        .limit(limit)
    )
    appointments = session.exec(statement).all()
    return appointments

@app.post("/appointments/", response_model=Appointment)
def create_appointment(appointment: AppointmentCreate, session: SessionDep):
    db_appointment = Appointment.model_validate(appointment)
    session.add(db_appointment)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="This specific window has already been reserved.",
        )
    session.refresh(db_appointment)
    return db_appointment

@app.patch("/appointments/{appointment_id}", response_model=Appointment)
def update_appointment(
    appointment_id: int, appointment: AppointmentUpdate, session: SessionDep
):
    appointment_db = session.get(Appointment, appointment_id)
    if not appointment_db:
        raise HTTPException(status_code=404, detail="Appointment not found")
    appointment_data = appointment.model_dump(exclude_unset=True)
    appointment_db.sqlmodel_update(appointment_data)
    session.add(appointment_db)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="This specific window has already been reserved.",
        )
    session.refresh(appointment_db)
    return appointment_db


@app.delete("/appointments/{appointment_id}")
def delete_appointment(appointment_id: int, session: SessionDep):
    appointment = session.get(Appointment, appointment_id)
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    session.delete(appointment)
    session.commit()
    return {"ok": True}
# End Appointments


# Patients
@app.post("/patients/", response_model=PatientPublic)
def create_patient(patient: PatientCreate, session: SessionDep):
    db_patient = Patient.model_validate(patient)
    session.add(db_patient)
    session.commit()
    session.refresh(db_patient)
    return db_patient

@app.get("/patients/", response_model=list[PatientPublic])
def read_patients(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    patients = session.exec(select(Patient).offset(offset).limit(limit)).all()
    return patients

@app.get("/patients/{patient_id}", response_model=PatientPublic)
def read_patient(patient_id: int, session: SessionDep):
    patient = session.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

@app.get("/patients-auth/{username}")
def read_patient_auth(username: str, session: SessionDep):
    statement = select(Patient).where(Patient.username == username).limit(1)
    patient = session.exec(statement).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return {
        "id": patient.id,
        "username": patient.username,
        "password_hash": patient.password_hash,
    }

@app.patch("/patients/{patient_id}", response_model=PatientPublic)
def update_patient(patient_id: int, patient: PatientUpdate, session: SessionDep):
    patient_db = session.get(Patient, patient_id)
    if not patient_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    patient_data = patient.model_dump(exclude_unset=True)
    patient_db.sqlmodel_update(patient_data)
    session.add(patient_db)
    session.commit()
    session.refresh(patient_db)
    return patient_db

@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: int, session: SessionDep):
    patient = session.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    session.delete(patient)
    session.commit()
    return {"ok": True}
# End Patients


# Doctors
@app.post("/doctors/", response_model=DoctorPublic)
def create_doctor(doctor: DoctorCreate, session: SessionDep):
    db_doctor = Doctor.model_validate(doctor)
    session.add(db_doctor)
    session.commit()
    session.refresh(db_doctor)
    return db_doctor

@app.get("/doctors/", response_model=list[DoctorPublic])
def read_doctors(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    doctors = session.exec(select(Doctor).offset(offset).limit(limit)).all()
    return doctors

@app.get("/doctors/{doctor_id}", response_model=DoctorPublic)
def read_doctor(doctor_id: int, session: SessionDep):
    doctor = session.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return doctor

@app.get("/doctors-auth/{username}")
def read_doctor_auth(username: str, session: SessionDep):
    statement = select(Doctor).where(Doctor.username == username).limit(1)
    doctor = session.exec(statement).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return {
        "id": doctor.id,
        "username": doctor.username,
        "password_hash": doctor.password_hash,
    }

@app.patch("/doctors/{doctor_id}", response_model=DoctorPublic)
def update_doctor(doctor_id: int, doctor: DoctorUpdate, session: SessionDep):
    doctor_db = session.get(Doctor, doctor_id)
    if not doctor_db:
        raise HTTPException(status_code=404, detail="Doctor not found")
    doctor_data = doctor.model_dump(exclude_unset=True)
    doctor_db.sqlmodel_update(doctor_data)
    session.add(doctor_db)
    session.commit()
    session.refresh(doctor_db)
    return doctor_db

@app.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: int, session: SessionDep):
    doctor = session.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    session.delete(doctor)
    session.commit()
    return {"ok": True}
# End Doctors


# Notifications
@app.post("/notifications/", response_model=Notification)
def create_notification(notification: NotificationCreate, session: SessionDep):
    db_notification = Notification.model_validate(notification)
    session.add(db_notification)
    session.commit()
    session.refresh(db_notification)
    return db_notification

@app.get("/notifications/", response_model=list[Notification])
def read_notifications(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    notifications = (
        session.exec(select(Notification).offset(offset).limit(limit)).all()
    )
    return notifications

@app.delete("/notifications/{notification_id}")
def delete_notification(notification_id: int, session: SessionDep):
    notification = session.get(Notification, notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    session.delete(notification)
    session.commit()
    return {"ok": True}
# End Notifications

'''
    temperature: float
    weight: float
    height: float
    blood_pressure: int
    diagnostic: str
    prescription: str
    report: str
'''

# Medical records
@app.post("/medical-records/", response_model=MedicalRecord)
def create_medical_record(record: MedicalRecordCreate, session: SessionDep):
    db_record = MedicalRecord.model_validate(record)
    session.add(db_record)
    session.commit()
    session.refresh(db_record)
    return db_record

@app.get("/medical-records/", response_model=list[MedicalRecord])
def read_medical_records(
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    records = (
        session.exec(select(MedicalRecord).offset(offset).limit(limit)).all()
    )
    return records

@app.get("/medical-records-patient/{patient_id}", response_model=list[MedicalRecord])
def read_patient_medical_records(
    patient_id: int,
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    statement = (
        select(MedicalRecord)
        .where(MedicalRecord.patient_id == patient_id)
        .order_by(MedicalRecord.date)
        .offset(offset)
        .limit(limit)
    )
    records = session.exec(statement).all()

    return records

@app.get("/medical-records-doctor/{doctor_id}", response_model=list[MedicalRecord])
def read_doctor_medical_records(
    doctor_id: int,
    session: SessionDep,
    offset: int = 0,
    limit: Annotated[int, Query(le=100)] = 100,
):
    statement = (
        select(MedicalRecord)
        .where(MedicalRecord.doctor_id == doctor_id)
        .order_by(MedicalRecord.date)
        .offset(offset)
        .limit(limit)
    )
    records = session.exec(statement).all()

    return records

@app.get("/medical-records/{record_id}", response_model=MedicalRecord)
def read_medical_record(record_id: int, session: SessionDep):
    record = session.get(MedicalRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Medical record not found")
    return record

@app.patch("/medical-records/{record_id}", response_model=MedicalRecord)
def update_medical_record(
    record_id: int, record: MedicalRecordUpdate, session: SessionDep
):
    record_db = session.get(MedicalRecord, record_id)
    if not record_db:
        raise HTTPException(status_code=404, detail="Medical record not found")
    record_data = record.model_dump(exclude_unset=True)
    record_db.sqlmodel_update(record_data)
    session.add(record_db)
    session.commit()
    session.refresh(record_db)
    return record_db

@app.delete("/medical-records/{record_id}")
def delete_medical_record(record_id: int, session: SessionDep):
    record = session.get(MedicalRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Medical record not found")
    session.delete(record)
    session.commit()
    return {"ok": True}