# Go-Network-Scanner

A high-performance, concurrent TCP port scanner built in Go. This tool leverages Go's native concurrency features (Goroutines and Channels) to scan network targets rapidly and efficiently.

## Motivation
My interest in networking started in the Minecraft community, where I was exploring server-side exploits and BungeeCord bypasses. To find those servers, I used different tools, but while they worked, I was missing a lot of features I wanted. I started looking into how things actually worked on the back end, and that's why I decided to build this. I wanted to move away from slow Python tools and build something in Go that is actually resource efficient and fast.

## Features
- **Concurrent Scanning**: Uses a worker pool pattern to scan multiple ports simultaneously.
- **Versatile Targets**: Supports single IP addresses, domain names, and CIDR blocks (e.g., `192.168.1.0/24`).
- **File Logging**: Automatically saves discovered open ports to a custom output file.
- **Detailed Output**: Features a verbose mode to track every connection attempt in real time.

## Installation
Ensure you have Go installed on your system, then clone the repository and build the binary:

```bash
go build -o scanner main.go
```
## Usage
Run the scanner using flags to specify your target and port range:

Scan a single domain
```bash 
./scanner -target example.com -port 20-100 -workers 2500
```

Scan a full subnet and save to file
```bash
./scanner -target 192.168.1.0/24 -port 80,443 -o results.txt
```

## Flags
- `-target`: The target IP, Domain, or CIDR block (Required)
- `-port`: Port or range (e.g., `80` or `1-1024`) (Required)
- `-workers`: Number of concurrent workers. (Default: 50) (Note: Optimized for I/O bound tasks; performance may vary based on file descriptor limits.)
- `-timeout`: Max wait time per port (e.g., `500ms` or `1s`) (Default: 250ms)
- `-o`: Path to output file for logging results (e.g., `results.txt`)
- `-v`: Enable verbose mode to see every connection attempt

## What i learned
- **Networking Fundamentals**: Deep dive into CIDR notations and how to handle IP ranges and subnets efficiently.
- **Data Representation**: Understanding the difference between unsigned and signed integers and how they affect memory.
- **Go Fundamentals**: Better understanding of how to use loops and structs to organize data.
- **Concurrency**: Learning how to use Goroutines and Channels to handle multiple tasks at the same time.
- **Architecture**: Implementing a worker pool to manage the workload and keep the scanner resource efficient.

## Roadmap
- [ ] **URL Sanitization**: Automatically strip `http(s)://` and trailing slashes from targets.
- [ ] **Service Fingerprinting**: Implement banner grabbing to identify running services and version info (e.g., SSH, HTTP, FTP).
- [ ] **Advanced Output**: Support for JSON and CSV export formats for better data processing.
- [ ] **Protocol Expansion**: Adding support for UDP scanning.

## Disclaimer
This tool is intended for educational and authorized security testing purposes only. Scanning networks without explicit permission from the owner is illegal and unethical. The developer is not responsible for any misuse of this tool.