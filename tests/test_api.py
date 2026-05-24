import sys
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from DB.main import app, create_db_and_tables, engine


DB_PATH = REPO_ROOT / "database.db"


def setup_module(module):
    if DB_PATH.exists():
        DB_PATH.unlink()
    create_db_and_tables()


def teardown_module(module):
    engine.dispose()
    if DB_PATH.exists():
        try:
            DB_PATH.unlink()
        except PermissionError:
            pass


def test_medical_record_flow():
    patient_payload = {
        "username": "p1",
        "password_hash": "x",
        "name": "Pat",
        "age": 30,
        "sex": "F",
        "phone": "123",
        "address": "A",
    }
    doctor_payload = {
        "username": "d1",
        "password_hash": "x",
        "name": "Dr",
    }

    with TestClient(app) as client:
        patient_res = client.post("/patients/", json=patient_payload)
        assert patient_res.status_code == 200
        patient_id = patient_res.json()["id"]

        doctor_res = client.post("/doctors/", json=doctor_payload)
        assert doctor_res.status_code == 200
        doctor_id = doctor_res.json()["id"]

        record_payload = {
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "temperature": 36.6,
            "weight": 70.5,
            "height": 1.75,
            "blood_pressure": 120,
            "diagnostic": "ok",
            "prescription": "none",
            "report": "report",
        }

        record_res = client.post("/medical-records/", json=record_payload)
        assert record_res.status_code == 200
        record = record_res.json()

        assert record["patient_id"] == patient_id
        assert record["doctor_id"] == doctor_id
        assert isinstance(record["temperature"], float)
        assert isinstance(record["blood_pressure"], int)

        record_id = record["id"]

        get_res = client.get(f"/medical-records/{record_id}")
        assert get_res.status_code == 200

        patch_res = client.patch(
            f"/medical-records/{record_id}", json={"diagnostic": "updated"}
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["diagnostic"] == "updated"

        list_patient_res = client.get(f"/medical-records-patient/{patient_id}")
        assert list_patient_res.status_code == 200
        assert len(list_patient_res.json()) >= 1

        list_doctor_res = client.get(f"/medical-records-doctor/{doctor_id}")
        assert list_doctor_res.status_code == 200
        assert len(list_doctor_res.json()) >= 1
