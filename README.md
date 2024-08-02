# Packet Sniffer Using Scapy

Welcome to the **Basic Packet Sniffer**! This Python script leverages the powerful Scapy library to capture and analyze network packets. It's a handy tool for network administrators and security enthusiasts to monitor network traffic and inspect HTTP requests.

## Features

- **Packet Capture**: Capture and analyze network packets in real-time.
- **Detailed HTTP Requests**: Extract and display HTTP request details including methods and URLs.
- **Color-Coded Output**: View captured data with clear, color-coded messages.
- **Customizable Interface**: Specify the network interface to capture packets from.

## Requirements

```sh
pip3 install -r requirements.txt
```

## Usage
```sh
python3 main.py -i <INTERFACE>
```

```sh
python3 main.py -i eth0
```

## Sample output
```sh
[+] 192.168.1.5 with port 12345 is making request at 192.168.1.1 on port 80
192.168.1.5 is making http_request at www.example.com/path using GET method
 HTTP data :-
...
Sniffer finds Something useful : Some raw data
```
