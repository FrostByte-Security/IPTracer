import json
import requests
from collections import defaultdict
import time

# Constants
IPINFO_TOKEN = 'ENTER_YOUR_API_KEY'  # Replace with your IPinfo API key
ABUSEIPDB_KEY = 'ENTER_YOUR_API_KEY'  # Replace with your AbuseIPDB API key

def read_json_logs(file_path):
    ip_details = defaultdict(lambda: {
        'timestamps': [],
        'versions': set(),
        'hasshs': set()
    })
    #  This will parse a DShield cowrie.json file and pull a list of unique IPs to be scanned later
    #  It will also add first and last timestamps, hassh, and version info if any
    with open(file_path, 'r') as file:
        for line in file:
            try:
                entry = json.loads(line)
                ip = entry.get('src_ip')
                if ip:
                    ip_details[ip]['timestamps'].append(entry.get('timestamp'))
                    if 'version' in entry:
                        ip_details[ip]['versions'].add(entry.get('version'))
                    if 'hassh' in entry:
                        ip_details[ip]['hasshs'].add(entry.get('hassh'))
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON on line: {e}")
                continue
    return ip_details

def get_ip_info(ip, details):
    #  Retrieves detailed information for a specific IP
    # IPinfo API call
    ipinfo_url = f'https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}'
    ipinfo_response = requests.get(ipinfo_url).json()

    # AbuseIPDB API call for reputation score
    abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    abuseipdb_response = requests.get(abuseipdb_url, headers=headers, params=params)
    abuse_confidence_score = abuseipdb_response.json()['data'][
        'abuseConfidenceScore'] if abuseipdb_response.status_code == 200 else 'API request failed'

    # Return collected data and add timestamps hassh and version info
    return {
        'IP': ip,
        'First Timestamp': min(details['timestamps'], default='N/A'),
        'Last Timestamp': max(details['timestamps'], default='N/A'),
        'Country': ipinfo_response.get('country', 'Unknown Country'),
        'City': ipinfo_response.get('city', 'Unknown City'),
        'Organization': ipinfo_response.get('org', 'No organization data available'),
        'Version': ', '.join(details.get('versions', [])),
        'HASSH': ', '.join(details['hasshs']),
        'Abuse Confidence Score': abuse_confidence_score,
    }
#  This function will search for the reverse dns using hackertarget, no api key is needed
def reverse_dns(ip):
    api_url = f"https://api.hackertarget.com/reversedns/?q={ip}"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.text.strip()
    else:
        return "Reverse DNS lookup failed"

def print_ip_details(ip_info):
    print("\n" + "-" * 60)
    print(f"Details for IP: {ip_info['IP']}")
    print("-" * 60)
    print(f"First Timestamp: {ip_info['First Timestamp']}")
    print(f"Last Timestamp:  {ip_info['Last Timestamp']}")
    print(f"Version:         {ip_info['Version']}")
    print(f"HASSH:           {ip_info['HASSH']}")
    print("-" * 60)
    print(f"Country:         {ip_info['Country']}")
    print(f"City:            {ip_info['City']}")
    print(f"Organization:    {ip_info['Organization']}")
    print(f"Abuse Score:     {ip_info['Abuse Confidence Score']}")
    print("-" * 60)

#  Returns Proxy data from proxycheck
def get_proxy_details(ip):
    api_key = 'ENTER_YOUR_API_KEY'  # Replace with your actual ProxyCheck.io API key
    url = f"https://proxycheck.io/v2/{ip}?key={api_key}&vpn=1&asn=1"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        ip_data = data.get(ip, {})
        proxy_details = {
            'Proxy': ip_data.get('proxy', 'no'),
            'Type': ip_data.get('type', 'N/A'),
            'Operator': ip_data.get('operator', {})
        }
        return proxy_details
    else:
        return {"error": "Failed to retrieve data"}

#  Prints the proxy details
def print_proxy_details(proxy_details):
    print("\nProxy Details:")
    print("-" * 20)
    print(f"Proxy: {proxy_details['Proxy']}")
    print(f"Type: {proxy_details['Type']}")
    print("Operator Info:")
    operator = proxy_details.get('Operator', {})
    if operator:
        print(f"  Name: {operator.get('name', 'N/A')}")
        print(f"  URL: {operator.get('url', 'N/A')}")
        print(f"  Anonymity: {operator.get('anonymity', 'N/A')}")
        print(f"  Popularity: {operator.get('popularity', 'N/A')}")
        print(f"  Protocols: {', '.join(operator.get('protocols', []))}")
        print("  Policies:")
        for key, value in operator.get('policies', {}).items():
            print(f"    {key}: {value}")
    else:
        print("  No operator information available.")

def user_choice():
    print('''           _ (`-.        .-') _   _  .-')     ('-.                  ('-.  _  .-')   
           ( (OO  )      (  OO) ) ( \( -O )   ( OO ).-.            _(  OO)( \( -O )  
  ,-.-')  _.`     \      /     '._ ,------.   / . --. /   .-----. (,------.,------.  
  |  |OO)(__...--''      |'--...__)|   /`. '  | \-.  \   '  .--./  |  .---'|   /`. ' 
  |  |  \ |  /  | |      '--.  .--'|  /  | |.-'-'  |  |  |  |('-.  |  |    |  /  | | 
  |  |(_/ |  |_.' |         |  |   |  |_.' | \| |_.'  | /_) |OO  )(|  '--. |  |_.' | 
 ,|  |_.' |  .___.'         |  |   |  .  '.'  |  .-.  | ||  |`-'|  |  .--' |  .  '.' 
(_|  |    |  |              |  |   |  |\  \   |  | |  |(_'  '--'\  |  `---.|  |\  \  
  `--'    `--'              `--'   `--' '--'  `--' `--'   `-----'  `------'`--' '--' ''')
    print("Please choose an option:")
    print("1. Search for a single IP")
    print("2. Scan multiple IPs from a JSON file")
    choice = input("Enter choice (1 or 2): ")
    return choice

def main():
    choice = user_choice()
    if choice == '1':
        ip = input("Enter the IP address to search: ")
        details = defaultdict(lambda: {
            'timestamps': ['N/A'],
            'versions': set(),
            'hasshs': set()
        })
        ip_info = get_ip_info(ip, details[ip])
        print_ip_details(ip_info)
        reverse_dns_result = reverse_dns(ip)
        print(f"Reverse DNS result for {ip}: {reverse_dns_result}")
        proxy_details = get_proxy_details(ip)
        if "error" not in proxy_details:
            print_proxy_details(proxy_details)
        else:
            print(proxy_details['error'])

    elif choice == '2':
        file_path = input("Enter the path to your JSON log file: ")
        ip_details = read_json_logs(file_path)
        print(f"Loaded {len(ip_details)} IPs to process.")

        for ip in ip_details.keys():
            ip_info = get_ip_info(ip, ip_details[ip])
            print_ip_details(ip_info)

            reverse_dns_result = reverse_dns(ip)
            print(f"Reverse DNS result for {ip}: {reverse_dns_result}")

            proxy_details = get_proxy_details(ip)
            if "error" not in proxy_details:
                print_proxy_details(proxy_details)
            else:
                print(proxy_details['error'])

            time.sleep(1)  # Delay to manage API rate limiting
    else:
        print("Invalid choice. Please run the script again and select either 1 or 2.")


if __name__ == "__main__":
    main()
