# SentinelSSH: Advanced CVE-2024-6387 Vulnerability Scanner

SentinelSSH is an advanced, high-performance SSH vulnerability scanner written in Go. It's specifically designed to detect the CVE-2024-6387 vulnerability in OpenSSH servers across various network environments.

## Installation

To install SentinelSSH, make sure you have Go installed on your system (version 1.16 or later), then run:

```bash
go install github.com/harshinsecurity/sentinelssh/cmd/sentinelssh@latest
```

Replace `yourusername` with the actual GitHub username where the project is hosted.

## Usage

After installation, you can run SentinelSSH directly from the command line:

```bash
sentinelssh [flags] [targets...]
```

### Flags

- `--port, -p`: Target port number (default: 22)
- `--timeout, -t`: Connection timeout in seconds (default: 5)
- `--concurrency, -c`: Number of concurrent scans (default: 100)
- `--output, -o`: Output file for detailed results (CSV format)
- `--file, -f`: File containing list of targets

### Examples

Scan a single IP:
```bash
sentinelssh 192.168.1.1
```

Scan a domain:
```bash
sentinelssh example.com
```

Scan multiple targets:
```bash
sentinelssh example.com 192.168.1.1 10.0.0.1
```

Scan targets from a file:
```bash
sentinelssh -f targets.txt
```

Save results to a CSV file:
```bash
sentinelssh -o results.csv 192.168.1.1 example.com
```

Custom port and higher concurrency:
```bash
sentinelssh --port 2222 --concurrency 200 192.168.1.0/24
```

## Features

- Targeted CVE-2024-6387 detection
- Support for IP addresses, domain names, and CIDR ranges
- High-speed concurrent scanning
- Comprehensive version analysis
- Detailed, color-coded console output
- CSV export for further analysis
- Customizable scan parameters

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
