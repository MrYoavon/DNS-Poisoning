from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

MY_IP = "192.168.1.108"

# Define a function to send test DNS packets
def send_test_packets():
    # Legitimate DNS response
    legitimate_response = IP(src="8.8.8.8", dst=MY_IP) / \
                          UDP(sport=53, dport=12345) / \
                          DNS(id=1234, qr=1, qd=DNSQR(qname="example.com"), \
                              an=DNSRR(rrname="example.com", rdata="93.184.216.34"))

    # DNS response with a suspicious IP
    suspicious_response = IP(src="8.8.8.8", dst=MY_IP) / \
                          UDP(sport=53, dport=12345) / \
                          DNS(id=1235, qr=1, qd=DNSQR(qname="malicious.com"), \
                              an=DNSRR(rrname="malicious.com", rdata="10.0.0.1"))

    # DNS response with a low TTL
    low_ttl_response = IP(src="8.8.8.8", dst=MY_IP, ttl=50) / \
                       UDP(sport=53, dport=12345) / \
                       DNS(id=1236, qr=1, qd=DNSQR(qname="lowttl.com"), \
                           an=DNSRR(rrname="lowttl.com", rdata="93.184.216.34"))

    # DNS poisoning attempt (multiple responses with the same transaction ID)
    first_poison_response = IP(src="8.8.8.8", dst=MY_IP) / \
                            UDP(sport=53, dport=12345) / \
                            DNS(id=1237, qr=1, qd=DNSQR(qname="poisoned.com"), \
                                an=DNSRR(rrname="poisoned.com", rdata="93.184.216.34"))

    second_poison_response = IP(src="8.8.4.4", dst=MY_IP) / \
                             UDP(sport=53, dport=12345) / \
                             DNS(id=1237, qr=1, qd=DNSQR(qname="poisoned.com"), \
                                 an=DNSRR(rrname="poisoned.com", rdata="1.1.1.1"))

    # Send packets
    print("Sending legitimate DNS response...")
    send(legitimate_response)

    print("Sending DNS response with a suspicious IP...")
    send(suspicious_response)

    print("Sending DNS response with a low TTL...")
    send(low_ttl_response)

    print("Sending first DNS poisoning response...")
    send(first_poison_response)

    print("Sending second DNS poisoning response...")
    send(second_poison_response)

if __name__ == "__main__":
    send_test_packets()
