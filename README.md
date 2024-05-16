# IP Tracer

IP Tracer is a powerful Python script designed for security analysts and enthusiasts. It allows users to analyze IP addresses to determine if they are associated with VPNs, proxies, or other anonymizing services. Additionally, the script provides detailed geolocation information, performs reverse DNS lookups, and retrieves security metrics from various online APIs.

## Features

-**DShield Cowrie Logs**: This script has an option to parse multiple unique IPs from a cowrie json file and output all related IP info.
- **VPN and Proxy Detection**: Identifies whether an IP address is associated with a VPN or proxy service.
- **Geolocation Information**: Retrieves detailed location information including country, city, and ISP details.
- **Reverse DNS Lookup**: Performs reverse DNS lookups to find domain names associated with IP addresses.
- **Security Assessments**: Integrates with APIs like AbuseIPDB to fetch reputation scores and other security-related data.

## Getting Started

Ensure you have signed up for free accounts at Abuseipdb, ipinfo.io, and proxycheck.io to get your API keys.

### Prerequisites
-API Keys for AbuseIPDB, ipinfo.io, and proxycheck.io ( will be adding virustotal in the future)
- Python 3.6 or higher
- `requests` library

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/Frostbyte-security/IP-Tracer.git
cd IP-Tracer

### Acknowledgments

IPinfo
ProxyCheck.io
AbuseIPDB
Hackertarget.com
