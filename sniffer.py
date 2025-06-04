import datetime
import threading
import time
import requests
import socketio
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import sniff

packets_buffer = []
SEND_INTERVAL = 5


def send_batched_packets(sio: socketio.Client):
    while True:
        time.sleep(SEND_INTERVAL)
        payload = packets_buffer.copy()

        if len(payload):
            try:
                # response = requests.post(BACKEND_URL, json=payload)
                # response.raise_for_status()
                sio.emit("NewPackets", data=payload)
                print(f"Sent {len(payload)} packets to backend")
                packets_buffer.clear()
            except requests.exceptions.RequestException:
                pass
                print("Failed Sending {} packet(s) to server".format(len(payload)))
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
        "src": {},
        "dest": {},
        "timestamp": datetime.datetime.fromtimestamp(float(packet.time)).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }

    # Handle IPv4/6 interfaces
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
    else:
        pass

    # Handle TCP/UDP
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
    else:
        pass

    if packet.haslayer(ICMP):
        packet_data = {**packet_data, "protocol": "ICMP"}

    # Extract Mac Address from the packet
    if packet.haslayer(Ether):
        packet_data = {
            **packet_data,
            "deviceId": packet[Ether].mac,
            "src": {**packet_data["src"], "mac": packet[Ether].src},
            "dest": {**packet_data["dest"], "mac": packet[Ether].dst},
        }

    # Handle ARP packets
    if packet.haslayer(ARP):
        packet_data = {**packet_data, "protocol": "ARP"}

    packets_buffer.append(packet_data)


def main():
    print("Starting packet sniffer...")
    thread = threading.Thread(target=send_batched_packets, daemon=True)
    thread.start()
    sniff(
        prn=handle_sniffed_packets,
        # count=10
    )  # Captures 10 packets; remove count for continuous sniffing


if __name__ == "__main__":
    main()
