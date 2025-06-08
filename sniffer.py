import datetime
import threading
import time
import socketio
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import sniff
from utils import BACKEND_URL, get_ip, get_mac

SEND_INTERVAL = 5
packets_buffer = []
buffer_lock = threading.Lock()


def send_batched_packets(sio: socketio.Client):
    while True:
        time.sleep(SEND_INTERVAL)
        with buffer_lock:
            if packets_buffer:
                payload = packets_buffer.copy()
                packets_buffer.clear()
                try:
                    sio.emit("NewPackets", data=payload)
                    print(f"Sent {len(payload)} packets to backend")
                except Exception as e:
                    print(f"Failed sending {len(payload)} packet(s) to server: {e}")
                    packets_buffer.extend(payload)


def handle_sniffed_packets(packet: Packet):
    if not (
        packet.haslayer(IP)
        or packet.haslayer(Ether)
        or packet.haslayer(UDP)
        or packet.haslayer(TCP)
        or packet.haslayer(ARP)
        or packet.haslayer(IPv6)
    ):
        return

    packet_data = {
        "src": {"ip": "N/A", "mac": "N/A", "port": "N/A"},
        "dest": {"ip": "N/A", "mac": "N/A", "port": "N/A"},
        "timestamp": datetime.datetime.fromtimestamp(float(packet.time)).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }

    if packet.haslayer(IP):
        packet_data = {
            **packet_data,
            "interface": "IPv4",
            "src": {**packet_data["src"], "ip": packet[IP].src},
            "dest": {**packet_data["dest"], "ip": packet[IP].dst},
            "protocol": packet[IP].proto,
        }
    elif packet.haslayer(IPv6):
        packet_data = {
            **packet_data,
            "interface": "IPv6",
            "src": {**packet_data["src"], "ip": packet[IPv6].src},
            "dest": {**packet_data["dest"], "ip": packet[IPv6].dst},
            "protocol": packet[IPv6].nh,
        }

    if packet.haslayer(TCP):
        packet_data = {
            **packet_data,
            "src": {**packet_data["src"], "port": packet[TCP].sport},
            "dest": {**packet_data["dest"], "port": packet[TCP].dport},
            "data": str(packet[TCP].payload),
            "protocol": "TCP",
        }
    elif packet.haslayer(UDP):
        packet_data = {
            **packet_data,
            "src": {**packet_data["src"], "port": packet[UDP].sport},
            "dest": {**packet_data["dest"], "port": packet[UDP].dport},
            "data": str(packet[UDP].payload),
            "protocol": "UDP",
        }

    if packet.haslayer(ICMP):
        packet_data = {**packet_data, "protocol": "ICMP"}

    if packet.haslayer(Ether):
        packet_data = {
            **packet_data,
            "deviceId": packet[Ether].src,
            "src": {**packet_data["src"], "mac": packet[Ether].src},
            "dest": {**packet_data["dest"], "mac": packet[Ether].dst},
        }

    if packet.haslayer(ARP):
        packet_data = {**packet_data, "protocol": "ARP"}

    with buffer_lock:
        packets_buffer.append(packet_data)


def main():
    print("Starting packet sniffer...")
    sio = socketio.Client()
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
        return
    thread = threading.Thread(target=send_batched_packets, args=(sio,), daemon=True)
    thread.start()
    sniff(prn=handle_sniffed_packets)


if __name__ == "__main__":
    main()
