#!/usr/bin/env python3

import struct
import random
import os

BASE_DIR = os.path.expanduser("~/Desktop/PacketHunter-main")
OUT_DIR = os.path.join(BASE_DIR, "frontend/public/demo-pcaps")

os.makedirs(OUT_DIR, exist_ok=True)


class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, "wb")
        self.write_global_header()
        self.timestamp = 1700000000

    def write_global_header(self):
        header = struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            1
        )
        self.file.write(header)

    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)

        self.file.write(
            struct.pack(
                "<IIII",
                ts_sec,
                ts_usec,
                len(data),
                len(data)
            )
        )

        self.file.write(data)
        self.timestamp += 1

    def close(self):
        self.file.close()


def ethernet(src, dst):
    return (
        bytes.fromhex(dst.replace(":", "")) +
        bytes.fromhex(src.replace(":", "")) +
        struct.pack(">H", 0x0800)
    )


def ip_header(src_ip, dst_ip, protocol, payload_len):
    total_len = 20 + payload_len

    header = struct.pack(
        ">BBHHHBBH",
        0x45,
        0,
        total_len,
        random.randint(1, 65535),
        0x4000,
        64,
        protocol,
        0
    )

    header += bytes(map(int, src_ip.split(".")))
    header += bytes(map(int, dst_ip.split(".")))

    return header


def tcp_header(src_port, dst_port, seq, ack, flags):
    return struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        0x50,
        flags,
        65535,
        0,
        0
    )


def udp_header(src_port, dst_port, payload_len):
    return struct.pack(
        ">HHHH",
        src_port,
        dst_port,
        8 + payload_len,
        0
    )


def tls_client_hello(sni):
    sni_bytes = sni.encode()

    sni_entry = (
        struct.pack(">BH", 0, len(sni_bytes)) +
        sni_bytes
    )

    sni_list = (
        struct.pack(">H", len(sni_entry)) +
        sni_entry
    )

    sni_extension = (
        struct.pack(">HH", 0, len(sni_list)) +
        sni_list
    )

    extensions = (
        struct.pack(">H", len(sni_extension)) +
        sni_extension
    )

    body = (
        struct.pack(">H", 0x0303) +
        bytes(random.getrandbits(8) for _ in range(32)) +
        b"\x00" +
        struct.pack(">H", 2) +
        struct.pack(">H", 0x1301) +
        b"\x01\x00" +
        extensions
    )

    handshake = (
        b"\x01" +
        len(body).to_bytes(3, "big") +
        body
    )

    return (
        b"\x16\x03\x01" +
        struct.pack(">H", len(handshake)) +
        handshake
    )


def dns_query(domain):
    txid = struct.pack(">H", random.randint(1, 65535))

    header = (
        txid +
        struct.pack(">H", 0x0100) +
        struct.pack(">HHHH", 1, 0, 0, 0)
    )

    question = b""

    for label in domain.split("."):
        question += bytes([len(label)])
        question += label.encode()

    question += b"\x00"
    question += struct.pack(">HH", 1, 1)

    return header + question


def add_tcp_connection(writer, src_ip, dst_ip, dst_port, sni=None):
    src_mac = "00:11:22:33:44:55"
    dst_mac = "AA:BB:CC:DD:EE:FF"

    src_port = random.randint(49152, 65000)
    seq = random.randint(1000, 90000)

    # SYN
    tcp = tcp_header(src_port, dst_port, seq, 0, 0x02)

    writer.write_packet(
        ethernet(src_mac, dst_mac) +
        ip_header(src_ip, dst_ip, 6, len(tcp)) +
        tcp
    )

    # SYN-ACK
    tcp = tcp_header(
        dst_port,
        src_port,
        seq + 1000,
        seq + 1,
        0x12
    )

    writer.write_packet(
        ethernet(dst_mac, src_mac) +
        ip_header(dst_ip, src_ip, 6, len(tcp)) +
        tcp
    )

    # ACK
    tcp = tcp_header(
        src_port,
        dst_port,
        seq + 1,
        seq + 1001,
        0x10
    )

    writer.write_packet(
        ethernet(src_mac, dst_mac) +
        ip_header(src_ip, dst_ip, 6, len(tcp)) +
        tcp
    )

    # TLS Client Hello
    if sni:
        payload = tls_client_hello(sni)

        tcp = tcp_header(
            src_port,
            dst_port,
            seq + 1,
            seq + 1001,
            0x18
        )

        writer.write_packet(
            ethernet(src_mac, dst_mac) +
            ip_header(
                src_ip,
                dst_ip,
                6,
                len(tcp) + len(payload)
            ) +
            tcp +
            payload
        )


def add_udp(writer, src_ip, dst_ip, dst_port):
    src_mac = "00:11:22:33:44:55"
    dst_mac = "AA:BB:CC:DD:EE:FF"

    src_port = random.randint(49152, 65000)

    payload = bytes(
        random.getrandbits(8)
        for _ in range(random.randint(30, 100))
    )

    udp = udp_header(
        src_port,
        dst_port,
        len(payload)
    )

    writer.write_packet(
        ethernet(src_mac, dst_mac) +
        ip_header(
            src_ip,
            dst_ip,
            17,
            len(udp) + len(payload)
        ) +
        udp +
        payload
    )


def create_basic():
    path = os.path.join(OUT_DIR, "basic-traffic.pcap")
    writer = PCAPWriter(path)

    # 3 TCP connections
    add_tcp_connection(
        writer,
        "192.168.1.10",
        "142.250.185.206",
        443,
        "www.google.com"
    )

    add_tcp_connection(
        writer,
        "192.168.1.10",
        "140.82.114.4",
        443,
        "github.com"
    )

    add_tcp_connection(
        writer,
        "192.168.1.10",
        "93.184.216.34",
        80,
        None
    )

    # 2 DNS packets
    add_udp(writer, "192.168.1.10", "8.8.8.8", 53)
    add_udp(writer, "192.168.1.10", "8.8.8.8", 53)

    writer.close()

    print("Created basic-traffic.pcap")


def create_mixed():
    path = os.path.join(OUT_DIR, "mixed-tcp-udp.pcap")
    writer = PCAPWriter(path)

    # TCP traffic
    for ip, domain in [
        ("142.250.185.206", "google.com"),
        ("157.240.1.35", "facebook.com"),
        ("104.16.85.20", "discord.com"),
        ("140.82.114.4", "github.com"),
        ("35.186.224.25", "zoom.us"),
    ]:
        add_tcp_connection(
            writer,
            "192.168.1.20",
            ip,
            443,
            domain
        )

    # Heavy UDP traffic
    for _ in range(15):
        add_udp(
            writer,
            "192.168.1.20",
            "8.8.8.8",
            53
        )

    writer.close()

    print("Created mixed-tcp-udp.pcap")


def create_app_classification():
    path = os.path.join(
        OUT_DIR,
        "application-classification.pcap"
    )

    writer = PCAPWriter(path)

    applications = [
        ("142.250.185.206", "www.google.com"),
        ("142.250.185.110", "www.youtube.com"),
        ("157.240.1.35", "www.facebook.com"),
        ("157.240.1.174", "www.instagram.com"),
        ("104.244.42.65", "twitter.com"),
        ("52.94.236.248", "www.amazon.com"),
        ("23.52.167.61", "www.netflix.com"),
        ("140.82.114.4", "github.com"),
        ("104.16.85.20", "discord.com"),
        ("35.186.224.25", "zoom.us"),
        ("35.186.227.140", "web.telegram.org"),
        ("99.86.0.100", "www.tiktok.com"),
        ("35.186.224.47", "open.spotify.com"),
    ]

    for dst_ip, domain in applications:
        add_tcp_connection(
            writer,
            "192.168.1.30",
            dst_ip,
            443,
            domain
        )

    writer.close()

    print("Created application-classification.pcap")


def create_blocking():
    path = os.path.join(
        OUT_DIR,
        "blocking-demo.pcap"
    )

    writer = PCAPWriter(path)

    # Normal traffic
    add_tcp_connection(
        writer,
        "192.168.1.40",
        "142.250.185.206",
        443,
        "www.google.com"
    )

    # YouTube traffic
    add_tcp_connection(
        writer,
        "192.168.1.40",
        "142.250.185.110",
        443,
        "www.youtube.com"
    )

    # Facebook traffic
    add_tcp_connection(
        writer,
        "192.168.1.40",
        "157.240.1.35",
        443,
        "www.facebook.com"
    )

    # Traffic from blocked source IP
    for _ in range(10):
        add_tcp_connection(
            writer,
            "192.168.1.50",
            "172.217.0.100",
            443,
            None
        )

    writer.close()

    print("Created blocking-demo.pcap")


def main():
    print("\nGenerating PacketHunter demo PCAPs...\n")

    create_basic()
    create_mixed()
    create_app_classification()
    create_blocking()

    print("\nDone.")
    print(f"Files created in: {OUT_DIR}\n")


if __name__ == "__main__":
    main()
