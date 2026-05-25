import datetime
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from DB.main import app, create_db_and_tables, engine


DB_PATH = REPO_ROOT / "database.db"
ATTEMPTS_PER_ROUND = 20
ROUNDS = 5


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


def _create_patient_and_doctor(client: TestClient, round_index: int) -> tuple[int, int]:
    patient_payload = {
        "username": f"p_conc_{round_index}",
        "password_hash": "x",
        "name": f"Pat {round_index}",
        "age": 28,
        "sex": "F",
        "phone": "456",
        "address": "B",
    }
    doctor_payload = {
        "username": f"d_conc_{round_index}",
        "password_hash": "x",
        "name": f"Dr {round_index}",
    }

    patient_res = client.post("/patients/", json=patient_payload)
    assert patient_res.status_code == 200
    patient_id = patient_res.json()["id"]

    doctor_res = client.post("/doctors/", json=doctor_payload)
    assert doctor_res.status_code == 200
    doctor_id = doctor_res.json()["id"]

    return patient_id, doctor_id


def test_concurrent_appointment_booking_threads():
    base_date = datetime.datetime(2030, 1, 1, 10, 0, 0)

    for round_index in range(ROUNDS):
        with TestClient(app) as client:
            patient_id, doctor_id = _create_patient_and_doctor(client, round_index)

        target = base_date + datetime.timedelta(days=round_index)
        payload = {
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "date": target.isoformat(),
        }
        barrier = threading.Barrier(ATTEMPTS_PER_ROUND)

        def attempt_booking() -> int:
            with TestClient(app) as thread_client:
                barrier.wait()
                resp = thread_client.post("/appointments/", json=payload)
                return resp.status_code

        with ThreadPoolExecutor(max_workers=ATTEMPTS_PER_ROUND) as executor:
            futures = [executor.submit(attempt_booking) for _ in range(ATTEMPTS_PER_ROUND)]
            status_codes = [future.result() for future in futures]

        assert status_codes.count(200) == 1
        assert status_codes.count(409) == ATTEMPTS_PER_ROUND - 1

        with TestClient(app) as client:
            list_res = client.get(f"/appointments-doctor/{doctor_id}")
            assert list_res.status_code == 200
            matches = 0
            for appt in list_res.json():
                appt_dt = datetime.datetime.fromisoformat(appt["date"])
                if appt_dt == target:
                    matches += 1
            assert matches == 1
