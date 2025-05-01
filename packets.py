from datetime import datetime
import socket
import struct
import textwrap
import time
import requests
import threading


TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

# Backend API endpoint (update if backend runs on a different host/port)
BACKEND_URL = "http://localhost:5000/packet"

# Interval in seconds to send batched keystrokes
SEND_INTERVAL = 10  # Adjust as needed (e.g., 5 seconds)

packet_buffer = []


def send_batched_packets():
    while True:
        time.sleep(SEND_INTERVAL)
        payload = packet_buffer.copy()
        try:
            response = requests.post(BACKEND_URL, json=payload)
            response.raise_for_status()
            print(f"Sent {len(payload)} packets to backend")
            packet_buffer.clear()
        except requests.exceptions.RequestException:
            pass
            packet_buffer.extend(payload)


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    thread = threading.Thread(target=send_batched_packets, daemon=True)
    thread.start()

    while True:
        raw_data, addr = conn.recvfrom(65565)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        packet = {
            "version": 0,
            "interface": "",
            "src": {"ip": "", "mac": src_mac, "port": ""},
            "dest": {"ip": "", "mac": dest_mac, "port": ""},
            "data": "",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # print("\nEthernet Frame :")
        # print(
        #     TAB_1
        #     + "Destination: {}, Source: {}, Protocol: {}".format(
        #         dest_mac, src_mac, eth_proto
        #     )
        # )
        # Check if network is IPV4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src_ip, dest_ip, ip_data) = (
                ipv4_packet(data)
            )

            # print(TAB_1 + "IPv4 Packet:")
            # print(
            #     TAB_2
            #     + "Version: {}, Header Length: {}, TTL: {}".format(
            #         version, header_length, ttl
            #     )
            # )
            # print(
            #     TAB_2
            #     + "Protocol: {}, Source: {}, Target: {}".format(proto, src_ip, dest_ip)
            # )
            packet.update(
                version=version,
                src={
                    "ip": src_ip,
                    "mac": packet["src"]["mac"],
                    "port": packet["src"]["port"],
                },
                dest={
                    "ip": dest_ip,
                    "mac": packet["dest"]["mac"],
                    "port": packet["dest"]["port"],
                },
                interface="IPv4",
                data=ip_data.hex(),
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(ip_data)
                # print(TAB_2 + "ICMP Packet:")
                # print(
                #     TAB_3
                #     + "Type: {}, Code: {}, Checksum: {}".format(
                #         icmp_type, code, checksum
                #     )
                # )
                # print(TAB_3 + "Data:")
                # print(format_multi_line(DATA_TAB_4, data))
                packet.update(
                    data=data,
                    protocol="ICMP",
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
            elif proto == 6:
                (
                    src_port,
                    dest_port,
                    sequence,
                    acknowledge,
                    offset,
                    flag_urg,
                    flag_ack,
                    flag_psh,
                    flag_rst,
                    flag_syn,
                    flag_fin,
                    tcp_data,
                ) = tcp_segment(ip_data)
                # print(TAB_2 + "TCP Segment:")
                # print(
                #     TAB_3
                #     + "Source Port: {}, Destination Port: {}".format(
                #         src_port, dest_port
                #     )
                # )
                # print(
                #     TAB_3
                #     + "Sequence: {}, Acknowledge: {}".format(sequence, acknowledge)
                # )
                # print(TAB_3 + "Flags:")
                # print(
                #     TAB_4
                #     + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(
                #         flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
                #     )
                # )
                # print(TAB_3 + "Data:")
                # print(format_multi_line(DATA_TAB_4, tcp_data))
                packet.update(
                    data=tcp_data.hex(),
                    protocol="TCP",
                    src={
                        "port": src_port,
                        "ip": packet["src"]["ip"],
                        "mac": packet["src"]["mac"],
                    },
                    dest={
                        "port": dest_port,
                        "ip": packet["dest"]["ip"],
                        "mac": packet["dest"]["mac"],
                    },
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )

            elif proto == 17:
                src_port, dest_port, length, udp_data = udp_segment(ip_data)
                # print(TAB_2 + "UDP Segment:")
                # print(
                #     TAB_3
                #     + "Source Port: {}, Destination Port: {}".format(
                #         src_port, dest_port
                #     )
                # )
                packet.update(
                    data=udp_data.hex(),
                    protocol="UDP",
                    src={
                        "port": src_port,
                        "ip": packet["src"]["ip"],
                        "mac": packet["src"]["mac"],
                    },
                    dest={
                        "port": dest_port,
                        "ip": packet["dest"]["ip"],
                        "mac": packet["dest"]["mac"],
                    },
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )

            else:
                pass
                # print(TAB_1 + "Data:")
                # print(format_multi_line(DATA_TAB_2, data))

        else:
            pass
            # print("Data:")
            # print(format_multi_line(DATA_TAB_1, data))

        print("\n")
        print(packet)

        packet_buffer.append(packet)


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


def get_ip_addr(addr):
    return ".".join(map(str, addr))


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])

    return (
        version,
        header_length,
        ttl,
        proto,
        get_ip_addr(src),
        get_ip_addr(target),
        data[header_length:],
    )


# unpack Ip packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[:4]


# unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledge, offset_reserved_flags) = struct.unpack(
        "! H H L L H", data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledge,
        offset,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:],
    )


# unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])


main()
