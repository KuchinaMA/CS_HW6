#!/usr/bin/env python3
import argparse
import os
import sys
import ipaddress
from scapy.all import *

TARGET_DOMAIN = b"rerand0m.ru."
FAKE_IP = "94.131.13.188"
TRACEROUTE_UDP_START = 33434

HOP_BASE_IP = ipaddress.IPv4Address("162.252.205.131")

SONG_LINES = [
    "i.walk.a.lonely.road",
    "the.only.one.that.i.have.ever.known",
    "dont.know.where.it.goes",
    "but.its.only.me.and.i.walk.alone",
    "i.walk.this.empty.street",
    "on.the.boulevard.of.broken.dreams",
    "where.the.city.sleeps",
    "and.im.the.only.one.and.i.walk.alone",
    "i.walk.alone.i.walk.alone",
    "i.walk.alone.and.i.walk.a",
    "my.shadow.walks.beside.me",
    "my.shallow.heart.beats",
    "sometimes.i.wish.someone.will.find.me",
    "till.then.i.walk.alone",
    "ah.ah.ah.ah.ah",
    "im.walking.down.the.line",
    "that.divides.me.somewhere.in.my.mind",
    "on.the.border.line",
    "read.between.the.lines",
    "check.my.vital.signs",
    "i.walk.alone.i.walk.alone",
    "till.then.i.walk.alone",
]

def send_dns_response(pkt, iface, ip_dst, mac_dst, answer=None, extra=None):
    sendp(
        Ether(src=get_if_hwaddr(iface), dst=mac_dst) /
        IP(src=FAKE_IP, dst=ip_dst) /
        UDP(sport=53, dport=pkt[UDP].sport) /
        DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=answer, ar=extra),
        iface=iface,
        verbose=0
    )

def extract_ptr_index(qname):
    try:
        q = qname.decode().lower().rstrip('.')
        if not q.endswith("in-addr.arpa"):
            return None
        parts = q.split('.')
        if len(parts) < 4:
            return None
        ip_parts = parts[:4]
        ip_str = '.'.join(reversed(ip_parts))
        if not ip_str.startswith("162.252.205."):
            return None
        ip_int = int(ipaddress.IPv4Address(ip_str))
        base_int = int(HOP_BASE_IP)
        idx = ip_int - base_int
        return idx if 0 <= idx < len(SONG_LINES) else None
    except:
        return None

def handle_dns(pkt, iface, ip_dst, mac_dst):
    if pkt[DNS].qd.qname == TARGET_DOMAIN:
        answer = DNSRR(rrname=TARGET_DOMAIN, type="A", ttl=60, rdata=FAKE_IP)
        send_dns_response(pkt, iface, ip_dst, mac_dst, answer=answer)
        return
    ptr_idx = extract_ptr_index(pkt[DNS].qd.qname)
    if ptr_idx is not None:
        name = SONG_LINES[ptr_idx] + "."
        hop_ip = str(HOP_BASE_IP + ptr_idx)
        answer = DNSRR(rrname=pkt[DNS].qd.qname, type="PTR", ttl=60, rdata=name)
        extra = DNSRR(rrname=name, type="A", ttl=60, rdata=hop_ip)
        send_dns_response(pkt, iface, ip_dst, mac_dst, answer=answer, extra=extra)

def build_icmp_payload(original_ip):
    h = original_ip.ihl * 4
    return bytes(original_ip)[:h + 8]

def handle_traceroute(pkt, iface, ip_dst, mac_dst):
    ttl = pkt[IP].ttl
    hop_index = ttl - 1
    if hop_index < 0:
        return
    if hop_index < len(SONG_LINES) - 1:
        hop_ip = str(HOP_BASE_IP + hop_index)
        icmp_layer = ICMP(type=11, code=0)
    else:
        hop_ip = str(HOP_BASE_IP + (len(SONG_LINES) - 1))
        icmp_layer = ICMP(type=3, code=3)
    payload = build_icmp_payload(pkt[IP])
    sendp(
        Ether(src=get_if_hwaddr(iface), dst=mac_dst) /
        IP(src=hop_ip, dst=ip_dst) /
        icmp_layer /
        Raw(payload),
        iface=iface,
        verbose=0
    )

def handle_icmp(pkt, iface, ip_dst, mac_dst):
    if pkt[ICMP].type == 8 and pkt[IP].dst == FAKE_IP:
        sendp(
            Ether(src=get_if_hwaddr(iface), dst=mac_dst) /
            IP(src=FAKE_IP, dst=ip_dst) /
            ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
            pkt[ICMP].payload,
            iface=iface,
            verbose=0
        )

def process_packet(pkt, iface):
    try:
        if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
            return

        mac_dst = pkt[Ether].src
        ip_dst = pkt[IP].src

        if pkt.haslayer(ICMP):
            handle_icmp(pkt, iface, ip_dst, mac_dst)
            return

        if pkt.haslayer(UDP):
            if pkt[UDP].dport == 53 and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                handle_dns(pkt, iface, ip_dst, mac_dst)
            elif pkt[IP].dst == FAKE_IP and pkt[UDP].dport >= TRACEROUTE_UDP_START:
                handle_traceroute(pkt, iface, ip_dst, mac_dst)

    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", "-i", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Need root privileges")
        sys.exit(1)
    iface = args.iface
    filter_str = f"(udp and (port 53 or dst host {FAKE_IP})) or (icmp and dst host {FAKE_IP})"
    sniff(
        iface=iface,
        filter=filter_str,
        prn=lambda p: process_packet(p, iface),
        store=0
    )

if __name__ == "__main__":
    main()