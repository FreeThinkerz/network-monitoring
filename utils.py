import socket
import uuid
import requests
import platform
from datetime import datetime

HOST_IP = "127.0.0.1"
HOST_PORT = "3000"
BACKEND_URL = f"http://{HOST_IP}:{HOST_PORT}/api"


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("89.207.132.170", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


def get_mac():
    return ":".join(
        ["{:02x}".format((uuid.getnode() >> i) & 0xFF) for i in range(0, 8 * 6, 8)][
            ::-1
        ]
    )


def get_device_id(mac, hostname, ip):
    try:
        # Check if device exists by MAC
        response = requests.get(f"{BACKEND_URL}/devices?mac={mac}")
        response.raise_for_status()
        devices = response.json().get("devices", [])
        if devices:
            return devices[0]["id"]  # Return existing device ID
        # Create new device
        payload = {
            "mac": mac,
            "name": hostname,
            "type": "workstation",
            "ip": ip,
            "os": platform.system() + " " + platform.release(),
            "manufacturer": "Unknown",
            "model": "Unknown",
            "lastSeen": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        response = requests.post(f"{BACKEND_URL}/devices", json=payload)
        response.raise_for_status()
        device = response.json()
        return device.get("id")
    except requests.exceptions.RequestException as e:
        print(f"Error getting/creating device ID: {e}")
        return None  # Return None to indicate failure
