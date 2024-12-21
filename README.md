# DNS Poisoning Detection and Testing

This project contains a Python script designed to detect potential DNS poisoning attacks in network traffic, as well as a testing script to simulate various DNS scenarios.

## Features

### Detection Script
The detection script monitors DNS traffic and flags the following suspicious behaviors:

1. **Multiple Responses for the Same Transaction ID**:
   Detects cases where multiple responses with the same transaction ID originate from different IP addresses, potentially indicating DNS poisoning.

2. **Unusual TTL (Time-to-Live) Values**:
   Flags responses with TTL values lower than a certain threshold (default: 60).

3. **Responses with Suspicious IP Addresses**:
   Identifies responses with IP addresses within specific private ranges, as defined by `suspicious_ip_addresses`.

### Testing Script
The testing script generates and sends DNS packets to simulate:

- Legitimate DNS responses.
- Responses containing suspicious IP addresses.
- Responses with low TTL values.
- Multiple conflicting responses (simulating DNS poisoning).

## File Structure

- **`dns_poisoning_detection.py`**: Contains the DNS poisoning detection logic.
- **`dns_testing_script.py`**: Sends test DNS packets to evaluate the detection script.

## Prerequisites

1. **Python 3.6+**
2. **Scapy Library**: Install it using pip:
   ```bash
   pip install scapy
   ```
3. **Administrator/Root Privileges**: Required to capture and send packets.

## How to Run

### 1. Running the Detection Script
Start the detection script to monitor DNS traffic:

```bash
sudo python dns_poisoning_detection.py
```

The script listens for DNS packets on UDP port 53 and analyzes them for suspicious behavior.

### 2. Running the Testing Script
In a separate terminal, run the testing script to generate DNS traffic:

```bash
sudo python dns_testing_script.py
```

The testing script sends a series of packets to the local machine’s IP (`MY_IP`).

## Configuration

### Detection Script

- **`suspicious_ip_addresses`**:
  Customize the list of suspicious IP ranges in CIDR notation:
  ```python
  suspicious_ip_addresses = ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"]
  ```

- **TTL Threshold**:
  Modify the TTL threshold in `detect_unusual_ttl`:
  ```python
  if ttl < 60:
  ```

### Testing Script

- **`MY_IP`**:
  Replace `MY_IP` with the local IP address of the machine running the detection script:
  ```python
  MY_IP = "192.168.1.108"
  ```

## Output

### Detection Script
The detection script prints alerts for detected issues:

- **Multiple Responses**:
  ```
  Potential DNS Poisoning detected for query example.com with transaction 1234 - 8.8.8.8, 8.8.4.4
  ```

- **Unusual TTL**:
  ```
  Unusual TTL: 50 in response for lowttl.com
  ```

- **Suspicious IPs**:
  ```
  Suspicious IP: 10.0.0.1 for malicious.com
  ```

### Testing Script
The testing script prints messages indicating the type of DNS packet being sent:

```plaintext
Sending legitimate DNS response...
Sending DNS response with a suspicious IP...
Sending DNS response with a low TTL...
Sending first DNS poisoning response...
Sending second DNS poisoning response...
```

## Notes

1. The detection script is designed to analyze traffic in real-time. Ensure it runs before starting the testing script.
2. Use in a controlled environment to avoid unintentional interference with real network traffic.

## Disclaimer
This script is intended for educational purposes and testing in secure, private environments. Do not use it for unauthorized network analysis or packet injection.

