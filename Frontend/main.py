import datetime
import os
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pwdlib import PasswordHash
from starlette.middleware.sessions import SessionMiddleware


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
DB_BASE_URL = os.getenv("DB_BASE_URL", "http://127.0.0.1:8001")
SESSION_SECRET = os.getenv("FRONTEND_SESSION_SECRET", "frontend_dev_secret")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_DISTRIBUTED_SYSTEMS_UADY_KEY")
ALGORITHM = "HS256"

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

password_hash_helper = PasswordHash.recommended()

app = FastAPI(title="Frontend - Appointment Manager")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)


def _add_flash(request: Request, message: str, level: str = "info") -> None:
	flashes = request.session.setdefault("flash", [])
	flashes.append({"message": message, "level": level})


def _pop_flash(request: Request) -> list[dict]:
	return request.session.pop("flash", [])


def _redirect(url: str, request: Optional[Request] = None, message: Optional[str] = None,
			  level: str = "info") -> RedirectResponse:
	if request and message:
		_add_flash(request, message, level)
	return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def _decode_token(token: str) -> dict:
	try:
		return jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
	except JWTError:
		try:
			return jwt.get_unverified_claims(token)
		except JWTError:
			return {}


def _get_user(request: Request) -> Optional[dict]:
	return request.session.get("user")


def _require_role(request: Request, role: str) -> Optional[dict]:
	user = _get_user(request)
	if not user or user.get("role") != role:
		return None
	return user


def _normalize_datetime(value: Any) -> datetime.datetime:
	if isinstance(value, datetime.datetime):
		return value
	return datetime.datetime.fromisoformat(value)


def _build_datetime(date_str: str, time_str: str) -> Optional[datetime.datetime]:
	try:
		date_obj = datetime.date.fromisoformat(date_str)
		time_obj = datetime.time.fromisoformat(time_str)
	except ValueError:
		return None
	return datetime.datetime.combine(date_obj, time_obj)


def _available_slots(date_str: str, appointments: list[dict]) -> list[str]:
	try:
		target_date = datetime.date.fromisoformat(date_str)
	except ValueError:
		return []
	taken = set()
	for appointment in appointments:
		appt_dt = _normalize_datetime(appointment.get("date"))
		if appt_dt.date() == target_date:
			taken.add(appt_dt.hour)
	slots = []
	for hour in range(9, 19):
		if hour not in taken:
			slots.append(f"{hour:02d}:00")
	return slots


def _safe_int(value: str) -> Optional[int]:
	try:
		return int(value)
	except (TypeError, ValueError):
		return None


def _safe_float(value: str) -> Optional[float]:
	try:
		return float(value)
	except (TypeError, ValueError):
		return None


async def _api_request(method: str, path: str, token: Optional[str] = None, **kwargs):
	headers = kwargs.pop("headers", {})
	if token:
		headers["Authorization"] = f"Bearer {token}"
	async with httpx.AsyncClient(timeout=10) as client:
		return await client.request(method, f"{API_BASE_URL}{path}", headers=headers, **kwargs)


async def _db_request(method: str, path: str, **kwargs):
	async with httpx.AsyncClient(timeout=10) as client:
		return await client.request(method, f"{DB_BASE_URL}{path}", **kwargs)


@app.get("/")
async def index(request: Request):
	user = _get_user(request)
	if user:
		return _redirect(f"/{user['role']}")
	return templates.TemplateResponse(
		"index.html",
		{"request": request, "flash": _pop_flash(request), "user": user},
	)


@app.get("/logout")
async def logout(request: Request):
	request.session.clear()
	return _redirect("/")


@app.post("/auth/login")
async def login(
	request: Request,
	role: str = Form(...),
	username: str = Form(...),
	password: str = Form(...),
):
	try:
		resp = await _api_request(
			"POST", "/token", data={"username": username, "password": password}
		)
	except httpx.RequestError:
		return _redirect("/", request, "API is unreachable.", "error")

	if resp.status_code != 200:
		return _redirect("/", request, "Invalid credentials.", "error")

	token = resp.json().get("access_token")
	if not token:
		return _redirect("/", request, "Token missing from response.", "error")
	claims = _decode_token(token)
	if not claims:
		return _redirect("/", request, "Unable to decode access token.", "error")

	role_claim = claims.get("role")
	internal_id = claims.get("internal_id")
	username_claim = claims.get("sub")

	if not role_claim or internal_id is None or not username_claim:
		return _redirect("/", request, "Access token missing required claims.", "error")

	if role and role_claim != role:
		return _redirect("/", request, "Role mismatch for this account.", "error")

	request.session["token"] = token
	request.session["user"] = {
		"username": username_claim,
		"role": role_claim,
		"internal_id": internal_id,
	}
	return _redirect(f"/{role_claim}")


@app.post("/auth/patient/register")
async def register_patient(
	request: Request,
	username: str = Form(...),
	password: str = Form(...),
	name: str = Form(...),
	age: int = Form(...),
	sex: str = Form(...),
	phone: str = Form(...),
	address: str = Form(...),
):
	payload = {
		"username": username,
		"password": password,
		"name": name,
		"age": age,
		"sex": sex,
		"phone": phone,
		"address": address,
	}
	try:
		resp = await _api_request("POST", "/patients/", json=payload)
	except httpx.RequestError:
		return _redirect("/", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/", request, "Patient registration failed.", "error")

	return await login(request, role="patient", username=username, password=password)


@app.post("/auth/doctor/register")
async def register_doctor(
	request: Request,
	username: str = Form(...),
	password: str = Form(...),
	name: str = Form(...),
):
	payload = {
		"username": username,
		"password_hash": password_hash_helper.hash(password),
		"name": name,
	}
	try:
		resp = await _db_request("POST", "/doctors/", json=payload)
	except httpx.RequestError:
		return _redirect("/", request, "DB layer is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/", request, "Doctor registration failed.", "error")

	return await login(request, role="doctor", username=username, password=password)


@app.get("/patient")
async def patient_dashboard(request: Request, doctor_id: Optional[int] = None,
							date: Optional[str] = None):
	user = _require_role(request, "patient")
	if not user:
		return _redirect("/", request, "Please sign in as a patient.", "error")

	token = request.session.get("token")
	appointments = []
	notifications = []
	history = None
	doctors = []
	available_slots = []

	try:
		resp = await _api_request(
			"GET", f"/appointments/patient/{user['internal_id']}", token=token
		)
		if resp.status_code == 200:
			appointments = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load appointments.", "error")

	try:
		resp = await _api_request("GET", "/notifications/", token=token)
		if resp.status_code == 200:
			notifications = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load notifications.", "error")

	try:
		resp = await _api_request(
			"GET", f"/reports/history/{user['internal_id']}", token=token
		)
		if resp.status_code == 200:
			history = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load medical records.", "error")

	try:
		resp = await _db_request("GET", "/doctors/")
		if resp.status_code == 200:
			doctors = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load doctor list.", "error")

	if doctor_id and date:
		try:
			resp = await _db_request("GET", f"/appointments-doctor/{doctor_id}")
			if resp.status_code == 200:
				available_slots = _available_slots(date, resp.json())
		except httpx.RequestError:
			_add_flash(request, "Unable to check availability.", "error")

	doctor_lookup = {doc["id"]: doc for doc in doctors}

	return templates.TemplateResponse(
		"patient.html",
		{
			"request": request,
			"user": user,
			"flash": _pop_flash(request),
			"appointments": appointments,
			"notifications": notifications,
			"history": history,
			"doctors": doctors,
			"doctor_lookup": doctor_lookup,
			"selected_doctor_id": doctor_id,
			"selected_date": date,
			"available_slots": available_slots,
		},
	)


@app.post("/patient/appointments")
async def patient_create_appointment(
	request: Request,
	doctor_id: int = Form(...),
	date: str = Form(...),
	time: str = Form(...),
):
	user = _require_role(request, "patient")
	if not user:
		return _redirect("/", request, "Please sign in as a patient.", "error")

	target = _build_datetime(date, time)
	if not target:
		return _redirect("/patient", request, "Invalid date or time.", "error")

	token = request.session.get("token")
	payload = {
		"patient_id": user["internal_id"],
		"doctor_id": doctor_id,
		"date": target.isoformat(),
	}
	try:
		resp = await _api_request("POST", "/appointments/", token=token, json=payload)
	except httpx.RequestError:
		return _redirect("/patient", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/patient", request, "Appointment creation failed.", "error")

	return _redirect("/patient", request, "Appointment created.", "success")


@app.post("/patient/appointments/{appointment_id}/cancel")
async def patient_cancel_appointment(request: Request, appointment_id: int):
	user = _require_role(request, "patient")
	if not user:
		return _redirect("/", request, "Please sign in as a patient.", "error")

	token = request.session.get("token")
	try:
		resp = await _api_request(
			"DELETE", f"/appointments/{appointment_id}", token=token
		)
	except httpx.RequestError:
		return _redirect("/patient", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 204):
		return _redirect("/patient", request, "Unable to cancel appointment.", "error")

	return _redirect("/patient", request, "Appointment canceled.", "success")


@app.post("/patient/appointments/{appointment_id}/reschedule")
async def patient_reschedule_appointment(
	request: Request,
	appointment_id: int,
	date: str = Form(...),
	time: str = Form(...),
):
	user = _require_role(request, "patient")
	if not user:
		return _redirect("/", request, "Please sign in as a patient.", "error")

	target = _build_datetime(date, time)
	if not target:
		return _redirect("/patient", request, "Invalid date or time.", "error")

	token = request.session.get("token")
	payload = {"date": target.isoformat()}
	try:
		resp = await _api_request(
			"PATCH", f"/appointments/{appointment_id}", token=token, json=payload
		)
	except httpx.RequestError:
		return _redirect("/patient", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/patient", request, "Unable to reschedule.", "error")

	return _redirect("/patient", request, "Appointment updated.", "success")


@app.post("/patient/notifications/{notification_id}/delete")
async def patient_delete_notification(request: Request, notification_id: int):
	user = _require_role(request, "patient")
	if not user:
		return _redirect("/", request, "Please sign in as a patient.", "error")

	try:
		resp = await _db_request("DELETE", f"/notifications/{notification_id}")
	except httpx.RequestError:
		return _redirect("/patient", request, "DB layer is unreachable.", "error")

	if resp.status_code not in (200, 204):
		return _redirect("/patient", request, "Unable to delete notification.", "error")

	return _redirect("/patient", request, "Notification deleted.", "success")


@app.get("/doctor")
async def doctor_dashboard(request: Request, patient_id: Optional[int] = None):
	user = _require_role(request, "doctor")
	if not user:
		return _redirect("/", request, "Please sign in as a doctor.", "error")

	token = request.session.get("token")
	appointments = []
	patients = []
	records = []
	history = None

	try:
		resp = await _api_request(
			"GET", f"/appointments/doctor/{user['internal_id']}", token=token
		)
		if resp.status_code == 200:
			appointments = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load appointments.", "error")

	try:
		resp = await _api_request("GET", "/patients/", token=token)
		if resp.status_code == 200:
			patients = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load patients.", "error")

	try:
		resp = await _db_request("GET", f"/medical-records-doctor/{user['internal_id']}")
		if resp.status_code == 200:
			records = resp.json()
	except httpx.RequestError:
		_add_flash(request, "Unable to load medical records.", "error")

	if patient_id:
		try:
			resp = await _api_request(
				"GET", f"/reports/history/{patient_id}", token=token
			)
			if resp.status_code == 200:
				history = resp.json()
		except httpx.RequestError:
			_add_flash(request, "Unable to load patient history.", "error")

	patient_lookup = {p["id"]: p for p in patients}

	return templates.TemplateResponse(
		"doctor.html",
		{
			"request": request,
			"user": user,
			"flash": _pop_flash(request),
			"appointments": appointments,
			"patients": patients,
			"records": records,
			"patient_lookup": patient_lookup,
			"history": history,
			"selected_patient_id": patient_id,
		},
	)


@app.post("/doctor/appointments/{appointment_id}/cancel")
async def doctor_cancel_appointment(request: Request, appointment_id: int):
	user = _require_role(request, "doctor")
	if not user:
		return _redirect("/", request, "Please sign in as a doctor.", "error")

	token = request.session.get("token")
	try:
		resp = await _api_request(
			"DELETE", f"/appointments/{appointment_id}", token=token
		)
	except httpx.RequestError:
		return _redirect("/doctor", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 204):
		return _redirect("/doctor", request, "Unable to cancel appointment.", "error")

	return _redirect("/doctor", request, "Appointment canceled.", "success")


@app.post("/doctor/records")
async def doctor_create_record(
	request: Request,
	patient_id: int = Form(...),
	temperature: float = Form(...),
	weight: float = Form(...),
	height: float = Form(...),
	blood_pressure: int = Form(...),
	diagnostic: str = Form(...),
	prescription: str = Form(...),
	report: str = Form(...),
):
	user = _require_role(request, "doctor")
	if not user:
		return _redirect("/", request, "Please sign in as a doctor.", "error")

	token = request.session.get("token")
	payload = {
		"patient_id": patient_id,
		"temperature": temperature,
		"weight": weight,
		"height": height,
		"blood_pressure": blood_pressure,
		"diagnostic": diagnostic,
		"prescription": prescription,
		"report": report,
	}
	try:
		resp = await _api_request("POST", "/medical-records/", token=token, json=payload)
	except httpx.RequestError:
		return _redirect("/doctor", request, "API is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/doctor", request, "Unable to create record.", "error")

	return _redirect("/doctor", request, "Medical record created.", "success")


@app.post("/doctor/records/update")
async def doctor_update_record(
	request: Request,
	record_id: str = Form(...),
	temperature: str = Form(""),
	weight: str = Form(""),
	height: str = Form(""),
	blood_pressure: str = Form(""),
	diagnostic: str = Form(""),
	prescription: str = Form(""),
	report: str = Form(""),
):
	user = _require_role(request, "doctor")
	if not user:
		return _redirect("/", request, "Please sign in as a doctor.", "error")

	record_id_int = _safe_int(record_id)
	if record_id_int is None:
		return _redirect("/doctor", request, "Invalid record id.", "error")

	payload: dict[str, Any] = {}
	if temperature:
		value = _safe_float(temperature)
		if value is None:
			return _redirect("/doctor", request, "Invalid temperature.", "error")
		payload["temperature"] = value
	if weight:
		value = _safe_float(weight)
		if value is None:
			return _redirect("/doctor", request, "Invalid weight.", "error")
		payload["weight"] = value
	if height:
		value = _safe_float(height)
		if value is None:
			return _redirect("/doctor", request, "Invalid height.", "error")
		payload["height"] = value
	if blood_pressure:
		value = _safe_int(blood_pressure)
		if value is None:
			return _redirect("/doctor", request, "Invalid blood pressure.", "error")
		payload["blood_pressure"] = value
	if diagnostic:
		payload["diagnostic"] = diagnostic
	if prescription:
		payload["prescription"] = prescription
	if report:
		payload["report"] = report

	if not payload:
		return _redirect("/doctor", request, "No updates provided.", "error")

	try:
		resp = await _db_request(
			"PATCH", f"/medical-records/{record_id_int}", json=payload
		)
	except httpx.RequestError:
		return _redirect("/doctor", request, "DB layer is unreachable.", "error")

	if resp.status_code not in (200, 201):
		return _redirect("/doctor", request, "Unable to update record.", "error")

	return _redirect("/doctor", request, "Medical record updated.", "success")
