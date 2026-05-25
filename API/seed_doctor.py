#!/usr/bin/env python3
import httpx
from pwdlib import PasswordHash

DB_LAYER_URL = "http://127.0.0.1:8001"

def seed_first_doctor():
    raw_password = "admin_password_2026"

    password_hash_helper = PasswordHash.recommended()
    hashed = password_hash_helper.hash(raw_password)
    
    first_doctor = {
        "username": "admin_doc",
        "password_hash": hashed,
        "name": "Dr. Chief Administrator"
    }
    
    print("Sending modern seeded doctor payload to database tier...")
    try:
        response = httpx.post(f"{DB_LAYER_URL}/doctors/", json=first_doctor)
        if response.status_code == 200:
            print("Success! First doctor created using modern Argon2id.")
            print(f"Username: admin_doc")
            print(f"Password: {raw_password}")
        else:
            print(f"Failed to seed: {response.status_code} - {response.text}")
    except httpx.ConnectError:
        print(f"Connection Error: Is your database layer app running on port 8001?")

if __name__ == "__main__":
    seed_first_doctor()