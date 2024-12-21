import ipaddress

from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP


responded_queries = {}
def detect_multiple_responses(packet):
    global responded_queries

    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:  # Check if it's a DNS response
            query_name = packet[DNS].qd.qname.decode('utf-8')
            transaction_id = packet[DNS].id
            src_ip = packet[IP].src

            if transaction_id not in responded_queries:
                # First response to the query
                responded_queries[transaction_id] = src_ip
            else:
                # At least the second response to the query
                print(f"Potential DNS Poisoning detected for query {query_name} with transaction {transaction_id} - {responded_queries[transaction_id]}, {src_ip}")
    except Exception as e:
        print("Error detect_multiple_responses: " + e)


def detect_unusual_ttl(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            if packet.haslayer(IP):
                ttl = packet[IP].ttl
                if ttl < 60:
                    print(f"Unusual TTL: {ttl} in response for {packet[DNS].qd.qname}")
    except Exception as e:
        print("Error detect_unusual_ttl: " + e)


def check_suspicious_ip(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            if packet[DNS].an:
                for answer in packet[DNS].an:
                    if isinstance(answer.rdata, str):  # Ensure it's an IP
                        if any(ipaddress.ip_address(answer.rdata) in ipaddress.ip_network(cidr) for cidr in suspicious_ip_addresses):
                            print(f"Suspicious IP: {answer.rdata} for {packet[DNS].qd.qname}")
    except Exception as e:
        print("Error check_suspicious_ip: " + e)


suspicious_ip_addresses = ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"]  # Adjust as needed

def dns_sniffer(packet):
    if packet.haslayer(DNS):
        detect_multiple_responses(packet)
        detect_unusual_ttl(packet)
        check_suspicious_ip(packet)

sniff(filter="udp port 53", prn=dns_sniffer)
