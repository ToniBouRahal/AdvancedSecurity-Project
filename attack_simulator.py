import requests
import time

TARGET_URL = "http://127.0.0.1:5000/login"

def brute_force():
    username = "alice"
    passwords = [f"pass{i}" for i in range(50)]  # many wrong passwords

    for pwd in passwords:
        data = {
            "username": username,
            "password": pwd
        }
        try:
            r = requests.post(TARGET_URL, data=data)
            print(f"Tried {pwd}, status={r.status_code}")
        except Exception as e:
            print("Error:", e)
        # Very fast brute-force: tiny sleep or none
        time.sleep(0.1)

if __name__ == "__main__":
    brute_force()
