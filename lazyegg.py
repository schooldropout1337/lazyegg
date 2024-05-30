import requests
from bs4 import BeautifulSoup
import argparse
import re
import socket
from urllib.parse import urlparse, urljoin

# Regular expression to match domains ending with valid TLDs
tld_regex = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:dev|stg|prod|local|com|net|org|edu|gov|mil|biz|xyz|co|us)\b'
)

# Regular expression to match IP addresses
ip_regex = re.compile(
    r'\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'  # First octet
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'     # Second octet
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'     # Third octet
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'     # Fourth octet
)

# Regular expression to detect leaked credentials in JS
leak_creds_regex = re.compile(
    r'(?i)((database|api_key|username|password|access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,@]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}["\']([0-9a-zA-Z\-_=@!#\$%\^&\*\(\)\+\[\]\{\}\|;:,<>\?~`]{1,64})["\']'
)

# Regular expression to extract cookies from JavaScript
cookie_regex = re.compile(r'document\.cookie\s*=\s*["\']([^"\']+)["\'];', re.IGNORECASE)

# Regular expression to extract localStorage entries from JavaScript
local_storage_regex = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)


# 0xRegex
Ox_regex = re.compile(r'\b\w+(?:\.\w+)?\s*\(\s*["\']([^"\']+)["\']\s*,\s*(["\'][^"\']*["\']|{[^}]*}|[^,)]+)', re.IGNORECASE)

# Load blacklist from hardcoded file
def load_blacklist():
    blacklist_file = 'blacklist.txt'
    with open(blacklist_file, 'r') as f:
        return [line.strip() for line in f.readlines()]

def extract_data(url, headers, extract_options):
    blacklist = load_blacklist()  # Load blacklist within this function
    try:
        is_js_file = url.endswith('.js')
        
        if ".js" in url:
            url = url.split(".js")[0] + ".js"
            is_js_file = url
         


        links = []  # Initialize links
        images = []  # Initialize images
        cookies = []  # Initialize cookies
        cookie_strings = []  # Initialize cookie_strings
        forms = []  # Initialize forms

        if is_js_file:
            scripts = [url]
        else:
            scripts = []
            # Sending a GET request to the URL with the supplied headers
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx and 5xx)
            # Parsing the HTML content of the page
            soup = BeautifulSoup(response.content, 'html.parser')
            # Extracting links
            links = []
            links = [urljoin(url, link.get('href')) for link in soup.find_all(['a', 'link']) if link.get('href')]
            # Extracting image URLs
            images = [urljoin(url, img.get('src')) for img in soup.find_all('img') if img.get('src')]
            # Extracting cookies
            cookies = response.cookies
            cookie_strings = [f"{cookie.name}={cookie.value}" for cookie in cookies]
            # Extracting forms and inputs
            forms = []
            for form in soup.find_all('form'):
                form_data = {'action': form.get('action'), 'method': form.get('method'), 'inputs': []}
                for input_tag in form.find_all('input'):
                    input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type'),
                    'value': input_tag.get('value'),
                }
                form_data['inputs'].append(input_data)
                forms.append(form_data)
                # Extracting JS URLs/domains/subdomains/IPs
                scripts = [urljoin(url, script.get('src')) for script in soup.find_all('script') if script.get('src')]
        js_urls = set()  # Using a set to avoid duplicate entries
        potential_domains = set()
        potential_ips = set()
        leaked_creds = []
        Oxcookies = []
        oxregex = []
        local_storage = []

        for script in scripts:
            hostname = urlparse(script).hostname
            if hostname in blacklist:
                print(f"Skipping blacklisted hostname: {hostname}")
                continue
            try:
                js_response = requests.get(script, headers=headers)
                js_response.raise_for_status()
                js_content = js_response.text

                # Extract URLs that start with http or https
                js_urls.update(re.findall(r'https?://[^\s\'"<>]+', js_content))

                # Extract domains, subdomains, and IP addresses
                potential_domains.update(re.findall(tld_regex, js_content))
                potential_ips.update(re.findall(ip_regex, js_content))

                # Find leaked credentials
                leaked_creds.extend(leak_creds_regex.findall(js_content))

                # Extracting cookies
                Oxcookies = cookie_regex.findall(js_content)

                # Extracting localStorage entries
                local_storage = local_storage_regex.findall(js_content)
                
                # OxRegex
                oxregex = Ox_regex.findall(js_content)

            except requests.RequestException as e:
                print(f"Warning: Could not fetch {script}: {e}")

        result = {}
        if extract_options['links']:
            result['links'] = links
        if extract_options['images']:
            result['images'] = images
        if extract_options['cookies']:
            result['cookies'] = cookie_strings
        if extract_options['forms']:
            result['forms'] = forms
        if extract_options['js_urls']:
            result['js_urls'] = list(js_urls)
        if extract_options['domains']:
            result['domains'] = list(potential_domains)
        if extract_options['ips']:
            result['ips'] = list(potential_ips)
        if extract_options['leaked_creds']:
            result['leaked_creds'] = leaked_creds
        if extract_options['oxcookies']:
            result['oxcookies'] = Oxcookies
        if extract_options['local_storage']:
            result['local_storage'] = local_storage
        if extract_options['oxregex']:
            result['oxregex'] = oxregex

        return result

    except requests.ConnectionError:
        print("Abort -  Connection Error")
        exit(1)
    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        exit(1)
    except Exception as err:
        print(f"An error occurred: {err}")
        exit(1)

def js_scan(host,wordlist):
    with open(wordlist, 'r') as f:
        urls = [line.strip() for line in f.readlines()]
        
    for url in urls:
        try:
            response = requests.get(host+'/'+url)
            if response.status_code == 200:
                print(f"URL: {host}/{url} - Status Code: 200 (OK)")
        
        except requests.RequestException as e:
            print(f"URL: {url} - Error: {e}")

def portscan(args):
    try:
        parsed_url = urlparse(args.url)
        domain = parsed_url.hostname
        url_port = parsed_url.port
        open_ports = []
        if args.portscan == 'default' or args.portscan == True:
            open_ports = DEFAULT_PORTS
        elif args.portscan:
            ports_input = args.portscan.split(',')
            for port_range in ports_input:
                if '-' in port_range:
                    start, end = map(int, port_range.split('-'))
                    open_ports.extend(range(start, end + 1))
                else:
                    open_ports.append(int(port_range))
        else:
            open_ports = DEFAULT_PORTS

        open_ports = check_open_ports(domain, url_port, open_ports)

        if open_ports:
            print(f"\n\033[1m\033[33mOpen Ports:\033[37m\033[22m")
            for port in open_ports:
                print(port)
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def check_open_ports(domain, url_port, open_ports):
    try:
        ip = socket.gethostbyname(domain)
        open_ports_found = []

        for port in open_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports_found.append(port)
            sock.close()

        return open_ports_found

    except socket.error as err:
        print(f"Socket error: {err}")
        return []

# Default ports for port scanning
DEFAULT_PORTS = [80, 443, 1194, 1723, 1701, 5000, 4500, 3000, 3001, 8080, 8443, 9990, 8085, 8000, 8081, 8181, 8888, 9200, 9300, 6379, 3306, 5432, 1433, 1521, 27017, 9042, 11211]

if __name__ == "__main__":
    try:
        # Parsing command-line arguments
        parser = argparse.ArgumentParser(description="LazyEgg extracts links, images, cookies, forms, JS URLs, localStorage, Host, IP, and leaked credentials from target.")
        parser.add_argument("url", help="URL to extract data from")
        parser.add_argument("-H", "--header", help="Headers in the format 'key: value'", action='append')
        parser.add_argument("--links", help="Extract links", action='store_true')
        parser.add_argument("--images", help="Extract images", action='store_true')
        parser.add_argument("--cookies", help="Extract cookies", action='store_true')
        parser.add_argument("--forms", help="Extract forms", action='store_true')
        parser.add_argument("--js_urls", help="Extract JS URLs", action='store_true')
        parser.add_argument("--domains", help="Extract domains/subdomains", action='store_true')
        parser.add_argument("--ips", help="Extract IP addresses", action='store_true')
        parser.add_argument("--leaked_creds", help="Extract leaked credentials", action='store_true')
        parser.add_argument("--oxcookies", help="Extract cookies in JavaScript", action='store_true')
        parser.add_argument("--local_storage", help="Extract localStorage entries", action='store_true')
        parser.add_argument("--oxregex", help="Extract OxRegex patterns", action='store_true')
        parser.add_argument('--js_scan', action='store_true', help='Enable scanning of JavaScript files. ./lazyegg.py target --js_scan -w wordlist.txt')
        parser.add_argument('--wordlist', '-w', help='Path to wordlist file for JS URL scanning')
        parser.add_argument("--portscan", nargs='?', const=True, help="Perform port scan. Specify ports or ranges like '8443,8080,3000' or '8000-9000' or 'default'")


        args = parser.parse_args()

        headers = {}
        if args.header:
            for header in args.header:
                key_value = header.split(':', 1)  # Ensure split only at the first colon
                if len(key_value) == 2:
                    headers[key_value[0].strip()] = key_value[1].strip()
                else:
                    print("Invalid header format:", header)
                    exit(1)

        # Determine if any extraction options were provided
        any_options_provided = any([
            args.links, args.images, args.cookies, args.forms, args.js_urls, 
            args.domains, args.ips, args.leaked_creds, args.oxcookies, 
            args.local_storage, args.oxregex, args.portscan, args.js_scan
        ])

        # If no specific options are provided, set all to True
        extract_options = {
            'links': args.links or not any_options_provided,
            'images': args.images or not any_options_provided,
            'cookies': args.cookies or not any_options_provided,
            'forms': args.forms or not any_options_provided,
            'js_urls': args.js_urls or not any_options_provided,
            'domains': args.domains or not any_options_provided,
            'ips': args.ips or not any_options_provided,
            'leaked_creds': args.leaked_creds or not any_options_provided,
            'oxcookies': args.oxcookies or not any_options_provided,
            'local_storage': args.local_storage or not any_options_provided,
            'oxregex': args.oxregex or not any_options_provided,
            'portscan': args.portscan or not any_options_provided,
            'js_scan': args.portscan or not any_options_provided,
        }

        if args.portscan:
            portscan(args)
        elif args.js_scan and args.wordlist:
            js_scan(args.url, args.wordlist)
        else:
            extracted_data = extract_data(args.url, headers, extract_options)
            for key, value in extracted_data.items():
                print(f"\n\033[1m\033[33m{key.capitalize()}:\033[37m\033[22m")
                for item in value:
                    print(item)
        

    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting gracefully.")
        exit(0)

