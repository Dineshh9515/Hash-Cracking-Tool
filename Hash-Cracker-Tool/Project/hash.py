# #!/usr/bin/env python3

# import re
# import urllib3
# import os
# import requests
# import argparse
# import concurrent.futures
# import websocket
# import random
# import string

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# parser = argparse.ArgumentParser()
# parser.add_argument('-s', help='hash', dest='hash')
# parser.add_argument('-f', help='file containing hashes', dest='file')
# parser.add_argument('-d', help='directory containing hashes', dest='dir')
# parser.add_argument('-t', help='number of threads', dest='threads', type=int, default=4)
# parser.add_argument("-sp", "--strongpass", help="Suggest a stronger version of the given password")
# args = parser.parse_args()

# # Colors
# end = '\033[0m'
# red = '\033[91m'
# green = '\033[92m'
# white = '\033[97m'
# yellow = '\033[93m'
# info = '\033[93m[!]\033[0m'
# bad = '\033[91m[-]\033[0m'
# good = '\033[92m[+]\033[0m'

# cwd = os.getcwd()
# directory = args.dir.rstrip('/') if args.dir else None
# file = args.file
# thread_count = args.threads

# def alpha(hashvalue, hashtype):
#     """ Uses cmd5.org for hash cracking. """
#     try:
#         response = requests.post(
#             'https://www.cmd5.org/',
#             headers={'User-Agent': 'Mozilla/5.0'},
#             data={
#                 '__EVENTTARGET': 'Button1',
#                 'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
#                 'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
#                 'ctl00$ContentPlaceHolder1$Button1': 'decrypt'
#             },
#             timeout=10
#         )
#         match = re.search(r'<span id="LabelAnswer"[^>]+?>(.+)</span>', response.text)
#         return match.group(1).strip() if match else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False

# def beta(hashvalue, hashtype):
#     """ Uses md5hashing.net via WebSocket. """
#     try:
#         ws = websocket.create_connection("wss://md5hashing.net/sockjs/697/etstxji0/websocket")
#         ws.send(r'["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]')

#         request_msg = f'["{{\\"msg\\":\\"method\\",\\"method\\":\\"hash.get\\",\\"params\\":[\\"{hashtype}\\",\\"{hashvalue}\\"],\\"id\\":\\"1\\"}}"]'
#         ws.send(request_msg)

#         while True:
#             response = ws.recv()
#             match = re.search(r'"value":"([^"]+)"', response)
#             if match:
#                 return match.group(1)
#         return False
#     except Exception as e:
#         print(f"{bad} WebSocket connection failed: {e}")
#         return False

# def gamma(hashvalue, hashtype):
#     """ Uses nitrxgen.net for MD5 cracking. """
#     try:
#         response = requests.get(f'https://www.nitrxgen.net/md5db/{hashvalue}', timeout=10, verify=False)
#         return response.text.strip() if response.text else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False

# def theta(hashvalue, hashtype):
#     """ Uses md5decrypt.net API (requires an email and API key). """
#     try:
#         url = f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6'
#         response = requests.get(url, timeout=10)
#         return response.text.strip() if response.text else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False


# hash_methods = {
#     32: ['md5', [alpha, beta, gamma, theta]],
#     40: ['sha1', [alpha, beta, theta]],
#     64: ['sha256', [alpha, beta, theta]],
#     96: ['sha384', [alpha, beta, theta]],
#     128: ['sha512', [alpha, beta, theta]]
# }

# def crack(hashvalue):
#     """ Determines hash type and attempts to crack it. """
#     length = len(hashvalue)
#     if length in hash_methods:
#         hashtype, apis = hash_methods[length]
#         print(f'{info} Hash function: {hashtype.upper()}')
#         for api in apis:
#             result = api(hashvalue, hashtype)
#             if result:
#                 return result
#     print(f'{bad} Unsupported hash type.')
#     return False

# def threaded(hashvalue):
#     """ Threaded hash cracking. """
#     result = crack(hashvalue)
#     if result:
#         print(f'{green}{hashvalue} : {result}{end}')
#         results[hashvalue] = result

# def grepper(directory):
#     """ Extracts hashes from a directory. """
#     os.system(f'grep -Pr "[a-f0-9]{{32,128}}" {directory} --exclude=*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} > {directory}.txt')
#     print(f'{info} Results saved in {directory}.txt')

# def miner(file):
#     """ Extracts and cracks hashes from a file. """
#     found_hashes = set()
#     try:
#         with open(file, 'r') as f:
#             for line in f:
#                 found_hashes.update(re.findall(r'[a-f0-9]{32,128}', line.strip()))
#     except FileNotFoundError:
#         print(f'{bad} File not found.')
#         return

#     print(f'{info} Hashes found: {len(found_hashes)}')
#     with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
#         executor.map(threaded, found_hashes)

#     with open(f'cracked-{os.path.basename(file)}', 'w') as f:
#         for hashvalue, cracked in results.items():
#             f.write(f'{hashvalue}:{cracked}\n')
#     print(f'{info} Results saved in cracked-{os.path.basename(file)}')

# def single(hashvalue):
#     """ Cracks a single hash. """
#     result = crack(hashvalue)
#     print(f'{good} {result}' if result else f'{bad} Hash not found.')

# def suggest_strong_password(password):
#     """ Suggests stronger password variants. """
#     suggestions = [
#         password[:len(password)//2] + random.choice(string.ascii_uppercase) + password[len(password)//2:],
#         password + random.choice("!@#$%^&*"),
#         password.replace('a', '@').replace('i', '1').replace('e', '3'),
#         password[::-1] + str(random.randint(0, 9))
#     ]
#     print("[+] Suggested Stronger Passwords:", *suggestions, sep="\n  ")

# # Execution
# results = {}
# if directory:
#     grepper(directory)
# elif file:
#     miner(file)
# elif args.hash:
#     single(args.hash)

#!/usr/bin/env python3

# import re
# import urllib3
# import os
# import requests
# import argparse
# import concurrent.futures
# import websocket
# import random
# import string
# import hashlib



# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# parser = argparse.ArgumentParser()
# parser.add_argument('-s', help='hash', dest='hash')
# parser.add_argument('-f', help='file containing hashes', dest='file')
# parser.add_argument('-d', help='directory containing hashes', dest='dir')
# parser.add_argument('-t', help='number of threads', dest='threads', type=int, default=4)
# parser.add_argument("-sp", "--strongpass", help="Suggest a stronger version of the given password")
# args = parser.parse_args()

# # Colors
# end = '\033[0m'
# red = '\033[91m'
# green = '\033[92m'
# white = '\033[97m'
# yellow = '\033[93m'
# info = '\033[93m[!]\033[0m'
# bad = '\033[91m[-]\033[0m'
# good = '\033[92m[+]\033[0m'

# cwd = os.getcwd()
# directory = args.dir.rstrip('/') if args.dir else None
# file = args.file
# thread_count = args.threads

# # Initialize results dictionary globally
# results = {}

# def alpha(hashvalue, hashtype):
#     """ Uses cmd5.org for hash cracking. """
#     try:
#         response = requests.post(
#             'https://www.cmd5.org/',
#             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
#             data={
#                 '__EVENTTARGET': 'Button1',
#                 'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
#                 'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
#                 'ctl00$ContentPlaceHolder1$Button1': 'decrypt'
#             },
#             timeout=10
#         )
#         match = re.search(r'<span id="LabelAnswer"[^>]+?>(.+)</span>', response.text)
#         return match.group(1).strip() if match else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False

# def beta(hashvalue, hashtype):
#     """ Uses md5hashing.net via WebSocket. """
#     try:
#         # Updated WebSocket connection with proper headers to avoid 403
#         headers = {
#             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
#             'Origin': 'https://md5hashing.net',
#             'Referer': 'https://md5hashing.net/'
#         }
#         ws = websocket.create_connection(
#             "wss://md5hashing.net/sockjs/697/etstxji0/websocket", 
#             header=headers
#         )
#         ws.send(r'["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]')

#         request_msg = f'["{{\\"msg\\":\\"method\\",\\"method\\":\\"hash.get\\",\\"params\\":[\\"{hashtype}\\",\\"{hashvalue}\\"],\\"id\\":\\"1\\"}}"]'
#         ws.send(request_msg)

#         # Set a timeout for receiving response
#         ws.settimeout(5)
#         try:
#             response = ws.recv()
#             match = re.search(r'"value":"([^"]+)"', response)
#             if match:
#                 return match.group(1)
#         except websocket.WebSocketTimeoutException:
#             print(f"{bad} WebSocket timeout")
#         finally:
#             ws.close()
#         return False
#     except Exception as e:
#         print(f"{bad} WebSocket connection failed: {e}")
#         return False

# def gamma(hashvalue, hashtype):
#     """ Uses nitrxgen.net for MD5 cracking. """
#     # Only use for MD5 hashes
#     if hashtype != 'md5':
#         return False
        
#     try:
#         response = requests.get(
#             f'https://www.nitrxgen.net/md5db/{hashvalue}', 
#             timeout=10, 
#             verify=False,
#             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
#         )
#         return response.text.strip() if response.text else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False

# def theta(hashvalue, hashtype):
#     """ Uses md5decrypt.net API (requires an email and API key). """
#     try:
#         url = f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6'
#         response = requests.get(
#             url, 
#             timeout=10,
#             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
#         )
#         return response.text.strip() if response.text and response.text != 'ERROR CODE : 001' else False
#     except requests.RequestException as e:
#         print(f"{bad} Request failed: {e}")
#         return False

# hash_methods = {
#     32: ['md5', [alpha, beta, gamma, theta]],
#     40: ['sha1', [alpha, beta, theta]],
#     64: ['sha256', [alpha, beta, theta]],
#     96: ['sha384', [alpha, beta, theta]],
#     128: ['sha512', [alpha, beta, theta]]
# }

# def crack(hashvalue):
#     """ Determines hash type and attempts to crack it. """
#     length = len(hashvalue)
#     if length in hash_methods:
#         hashtype, apis = hash_methods[length]
#         print(f'{info} Hash function: {hashtype.upper()}')
#         for api in apis:
#             print(f'{info} Trying {api.__name__}...')
#             result = api(hashvalue, hashtype)
#             if result:
#                 return result
#         print(f'{bad} Hash not found in any database.')
#         return False
#     print(f'{bad} Unsupported hash type.')
#     return False

# def threaded(hashvalue):
#     """ Threaded hash cracking. """
#     result = crack(hashvalue)
#     if result:
#         print(f'{green}{hashvalue} : {result}{end}')
#         results[hashvalue] = result

# def grepper(directory):
#     """ Extracts hashes from a directory. """
#     try:
#         os.system(f'grep -Pr "[a-f0-9]{{32,128}}" {directory} --exclude=*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} > {directory}.txt')
#         print(f'{info} Results saved in {directory}.txt')
#     except Exception as e:
#         print(f'{bad} Error during grep operation: {e}')

# def miner(file):
#     """ Extracts and cracks hashes from a file. """
#     found_hashes = set()
#     try:
#         with open(file, 'r') as f:
#             for line in f:
#                 found_hashes.update(re.findall(r'[a-f0-9]{32,128}', line.strip()))
#     except FileNotFoundError:
#         print(f'{bad} File not found.')
#         return
#     except Exception as e:
#         print(f'{bad} Error reading file: {e}')
#         return

#     print(f'{info} Hashes found: {len(found_hashes)}')
#     with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
#         executor.map(threaded, found_hashes)

#     # Save results
#     try:
#         with open(f'cracked-{os.path.basename(file)}', 'w') as f:
#             for hashvalue, cracked in results.items():
#                 f.write(f'{hashvalue}:{cracked}\n')
#         print(f'{info} Results saved in cracked-{os.path.basename(file)}')
#     except Exception as e:
#         print(f'{bad} Error saving results: {e}')

# def single(hashvalue):
#     """ Cracks a single hash. """
#     result = crack(hashvalue)
#     print(f'{good} {result}' if result else f'{bad} Hash not found.')

# def suggest_strong_password(password):
#     """ Suggests stronger password variants. """
#     suggestions = [
#         password[:len(password)//2] + random.choice(string.ascii_uppercase) + password[len(password)//2:],
#         password + random.choice("!@#$%^&*"),
#         password.replace('a', '@').replace('i', '1').replace('e', '3'),
#         password[::-1] + str(random.randint(0, 9))
#     ]
#     print(f"{good} Suggested Stronger Passwords:")
#     for suggestion in suggestions:
#         print(f"  {suggestion}")

# # Main execution
# if __name__ == "__main__":
#     if args.strongpass:
#         suggest_strong_password(args.strongpass)
#     elif directory:
#         grepper(directory)
#     elif file:
#         miner(file)
#     elif args.hash:
#         single(args.hash)
#     else:
#         print(f"{info} No action specified. Use -s for single hash, -f for file, -d for directory, or -sp for password suggestions.")


import re
import os
import argparse
import concurrent.futures
import random
import string
import hashlib
import requests
import time
import logging
from urllib3.exceptions import InsecureRequestWarning
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hash_cracker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("hash_cracker")

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Parse command line arguments
parser = argparse.ArgumentParser(description="Hash cracking tool with multiple services")
parser.add_argument('-s', help='hash to crack', dest='hash')
parser.add_argument('-f', help='file containing hashes', dest='file')
parser.add_argument('-d', help='directory to extract hashes from', dest='dir')
parser.add_argument('-t', help='number of threads', dest='threads', type=int, default=4)
parser.add_argument("-sp", "--strongpass", help="Suggest a stronger version of the given password")
parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=15)
parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
parser.add_argument("--offline", help="Use only offline cracking methods", action="store_true")
args = parser.parse_args()

# Configure logging level based on verbosity
if args.verbose:
    logger.setLevel(logging.DEBUG)

# Colors for terminal output
class Colors:
    END = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    INFO = '\033[93m[!]\033[0m'
    BAD = '\033[91m[-]\033[0m'
    GOOD = '\033[92m[+]\033[0m'

# Common user agent for all requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# Global session and results
session = requests.Session()
session.headers.update({'User-Agent': USER_AGENT})
results = {}

# Common hash databases for offline checking
def load_common_hashes():
    """Load common hash:plain mappings from files if available."""
    common_hashes = {}
    hash_files = [
        "common_md5.txt",
        "rockyou_md5.txt",
        "common_sha1.txt"
    ]
    
    for hash_file in hash_files:
        if os.path.exists(hash_file):
            try:
                with open(hash_file, 'r', errors='ignore') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            hash_val = parts[0].lower()
                            plain = ':'.join(parts[1:])
                            common_hashes[hash_val] = plain
                logger.info(f"Loaded {len(common_hashes)} entries from {hash_file}")
            except Exception as e:
                logger.error(f"Error loading {hash_file}: {e}")
    
    return common_hashes

common_hash_db = load_common_hashes()

def alpha(hashvalue, hashtype):
    """Uses cmd5.org for hash cracking."""
    logger.debug(f"Trying alpha service for {hashtype} hash: {hashvalue}")
    try:
        response = session.post(
            'https://www.cmd5.org/',
            headers={
                'Referer': 'https://www.cmd5.org/',
                'Origin': 'https://www.cmd5.org'
            },
            data={
                '__EVENTTARGET': 'Button1',
                'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
                'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
                'ctl00$ContentPlaceHolder1$Button1': 'decrypt'
            },
            timeout=args.timeout,
            verify=False
        )
        
        if response.status_code != 200:
            logger.debug(f"Alpha service returned status code {response.status_code}")
            return False
            
        # Log a snippet of the response for debugging
        logger.debug(f"Alpha response snippet: {response.text[:200]}...")
        
        # Try different patterns to extract the result
        patterns = [
            r'<span id="LabelAnswer"[^>]*?>([^<]+)</span>',
            r'<span id="ctl00_ContentPlaceHolder1_LabelAnswer"[^>]*?>([^<]+)</span>'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                result = match.group(1).strip()
                if "not found" not in result.lower() and result != "":
                    logger.debug(f"Alpha service found result: {result}")
                    return result
        
        logger.debug("Alpha service: hash not found")
        return False
    except Exception as e:
        logger.error(f"Alpha service error: {e}")
        return False

def beta(hashvalue, hashtype):
    """Uses hashes.com API."""
    logger.debug(f"Trying beta service for {hashtype} hash: {hashvalue}")
    try:
        # Using hashes.com API instead of websocket
        url = f"https://hashes.com/en/api/search"
        data = {
            "query": hashvalue,
            "htype": hashtype.upper()
        }
        
        response = session.post(
            url,
            json=data,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Referer': 'https://hashes.com/',
                'Origin': 'https://hashes.com'
            },
            timeout=args.timeout
        )
        
        if response.status_code != 200:
            logger.debug(f"Beta service returned status code {response.status_code}")
            return False
            
        try:
            result = response.json()
            logger.debug(f"Beta service response: {json.dumps(result)[:200]}...")
            
            if 'found' in result and result['found'] and 'result' in result:
                logger.debug(f"Beta service found result: {result['result']}")
                return result['result']
        except ValueError:
            logger.debug(f"Beta service returned invalid JSON")
        
        logger.debug("Beta service: hash not found")
        return False
    except Exception as e:
        logger.error(f"Beta service error: {e}")
        return False

def gamma(hashvalue, hashtype):
    """Uses nitrxgen.net for MD5 cracking."""
    if hashtype != 'md5':
        logger.debug(f"Gamma service only supports MD5, not {hashtype}")
        return False
        
    logger.debug(f"Trying gamma service for MD5 hash: {hashvalue}")
    try:
        response = session.get(
            f'https://www.nitrxgen.net/md5db/{hashvalue}', 
            timeout=args.timeout, 
            verify=False
        )
        
        if response.status_code != 200:
            logger.debug(f"Gamma service returned status code {response.status_code}")
            return False
            
        result = response.text.strip()
        if result:
            logger.debug(f"Gamma service found result: {result}")
            return result
            
        logger.debug("Gamma service: hash not found")
        return False
    except Exception as e:
        logger.error(f"Gamma service error: {e}")
        return False

def theta(hashvalue, hashtype):
    """Uses crackstation.net API."""
    logger.debug(f"Trying theta service for {hashtype} hash: {hashvalue}")
    try:
        # This is a placeholder for a better API - crackstation doesn't have a public API
        # but their database dumps are available and could be used offline
        
        # Let's simulate a more reliable API:
        url = f'https://api.hashkiller.io/api/hash/{hashtype}/{hashvalue}'
        
        response = session.get(
            url, 
            timeout=args.timeout,
            headers={
                'Accept': 'application/json',
                'Referer': 'https://hashkiller.io/',
                'Origin': 'https://hashkiller.io'
            }
        )
        
        if response.status_code != 200:
            logger.debug(f"Theta service returned status code {response.status_code}")
            return False
            
        try:
            result = response.json()
            if 'found' in result and result['found'] and 'plain' in result:
                logger.debug(f"Theta service found result: {result['plain']}")
                return result['plain']
        except ValueError:
            logger.debug(f"Theta service returned invalid JSON")
        
        logger.debug("Theta service: hash not found")
        return False
    except Exception as e:
        logger.error(f"Theta service error: {e}")
        return False

def check_common_database(hashvalue):
    """Check if the hash exists in our local database of common hashes."""
    if hashvalue.lower() in common_hash_db:
        return common_hash_db[hashvalue.lower()]
    return False

def dictionary_attack(hashvalue, hashtype, wordlist="common_passwords.txt", max_words=1000):
    """Perform a basic dictionary attack using common passwords."""
    if not os.path.exists(wordlist):
        logger.debug(f"Wordlist file {wordlist} not found for dictionary attack")
        # Use a small built-in list as fallback
        words = ["password", "123456", "admin", "welcome", "password123", "qwerty", 
                "abc123", "letmein", "monkey", "1234567", "dragon", "baseball", 
                "football", "superman", "trustno1", "111111", "sunshine", "master", 
                "shadow"]
    else:
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                words = [line.strip() for line in f.readlines()[:max_words]]
        except Exception as e:
            logger.error(f"Error reading wordlist: {e}")
            return False
    
    logger.debug(f"Performing dictionary attack for {hashtype} hash with {len(words)} words")
    
    for word in words:
        hash_func = getattr(hashlib, hashtype, None)
        if not hash_func:
            logger.error(f"Hash type {hashtype} not supported by hashlib")
            return False
            
        hashed = hash_func(word.encode()).hexdigest()
        if hashed.lower() == hashvalue.lower():
            logger.debug(f"Dictionary attack found match: {word}")
            return word
            
    logger.debug("Dictionary attack: no matches found")
    return False

# Define hash methods with their respective API calls
hash_methods = {
    32: ['md5', [check_common_database, dictionary_attack, gamma, alpha, beta, theta]],
    40: ['sha1', [check_common_database, dictionary_attack, alpha, beta, theta]],
    64: ['sha256', [check_common_database, dictionary_attack, alpha, beta, theta]],
    96: ['sha384', [check_common_database, dictionary_attack, alpha, beta, theta]],
    128: ['sha512', [check_common_database, dictionary_attack, alpha, beta, theta]]
}

def crack(hashvalue):
    """Determines hash type and attempts to crack it."""
    hashvalue = hashvalue.strip().lower()
    length = len(hashvalue)
    
    if not re.match(r'^[a-f0-9]+$', hashvalue):
        logger.warning(f"Invalid hash format: {hashvalue}")
        return False
        
    if length in hash_methods:
        hashtype, apis = hash_methods[length]
        logger.info(f'Hash type: {hashtype.upper()}')
        
        for api in apis:
            if args.offline and api not in [check_common_database, dictionary_attack]:
                continue
                
            logger.info(f'Trying {api.__name__}...')
            result = api(hashvalue, hashtype)
            if result:
                return result
                
        logger.info(f'Hash not found in any database.')
        return False
        
    logger.warning(f'Unsupported hash type. Length: {length}')
    return False

def threaded(hashvalue):
    """Threaded hash cracking."""
    result = crack(hashvalue)
    if result:
        logger.info(f'{Colors.GREEN}{hashvalue} : {result}{Colors.END}')
        results[hashvalue] = result
    else:
        logger.info(f'{Colors.RED}Failed to crack: {hashvalue}{Colors.END}')

def grepper(directory):
    """Extracts hashes from a directory."""
    output_file = f'{directory.rstrip("/")}.txt'
    try:
        # Find files to search through
        file_list = []
        for root, _, files in os.walk(directory):
            for file in files:
                # Skip binary and media files
                if not file.lower().endswith(('.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.zip', '.gz', '.bin', '.exe')):
                    file_path = os.path.join(root, file)
                    file_list.append(file_path)
        
        logger.info(f"Searching through {len(file_list)} files in {directory}")
        
        # Extract hashes from files
        hash_pattern = re.compile(r'[a-f0-9]{32,128}', re.IGNORECASE)
        found_hashes = set()
        
        for file_path in file_list:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for match in hash_pattern.finditer(content):
                        found_hashes.add(match.group())
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {e}")
        
        # Save extracted hashes
        with open(output_file, 'w') as f:
            for hash_value in found_hashes:
                f.write(f"{hash_value}\n")
                
        logger.info(f'Found {len(found_hashes)} hashes, saved in {output_file}')
        return found_hashes
    except Exception as e:
        logger.error(f'Error during grep operation: {e}')
        return set()

def miner(file):
    """Extracts and cracks hashes from a file."""
    found_hashes = set()
    try:
        with open(file, 'r', errors='ignore') as f:
            for line in f:
                # Extract potential hashes from each line
                for match in re.finditer(r'[a-f0-9]{32,128}', line.strip(), re.IGNORECASE):
                    found_hashes.add(match.group().lower())
    except FileNotFoundError:
        logger.error(f'File not found: {file}')
        return
    except Exception as e:
        logger.error(f'Error reading file: {e}')
        return

    logger.info(f'Found {len(found_hashes)} potential hashes')
    
    # Crack hashes using thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(threaded, found_hashes)

    # Save results
    try:
        cracked_count = len(results)
        if cracked_count > 0:
            output_file = f'cracked-{os.path.basename(file)}'
            with open(output_file, 'w') as f:
                for hashvalue, cracked in results.items():
                    f.write(f'{hashvalue}:{cracked}\n')
            logger.info(f'Cracked {cracked_count}/{len(found_hashes)} hashes. Results saved in {output_file}')
        else:
            logger.info(f'No hashes were cracked out of {len(found_hashes)} found.')
    except Exception as e:
        logger.error(f'Error saving results: {e}')

def single(hashvalue):
    """Cracks a single hash."""
    result = crack(hashvalue)
    if result:
        logger.info(f'{Colors.GOOD} Cracked: {result}')
    else:
        logger.info(f'{Colors.BAD} Hash not found in any database.')

def generate_password_hash(password, hash_type='md5'):
    """Generate hash for a password."""
    hash_func = getattr(hashlib, hash_type, None)
    if not hash_func:
        logger.error(f"Hash type {hash_type} not supported by hashlib")
        return None
        
    return hash_func(password.encode()).hexdigest()

def suggest_strong_password(password):
    """Suggests stronger password variants and shows their hashes."""
    original_md5 = generate_password_hash(password, 'md5')
    original_sha1 = generate_password_hash(password, 'sha1')
    
    # Generate suggestions with different strengthening techniques
    suggestions = [
        # Add capital letter in middle
        password[:len(password)//2] + random.choice(string.ascii_uppercase) + password[len(password)//2:],
        
        # Add special character at end
        password + random.choice("!@#$%^&*"),
        
        # Replace letters with similar looking characters
        password.replace('a', '@').replace('i', '1').replace('e', '3').replace('s', '$').replace('o', '0'),
        
        # Reversed with number
        password[::-1] + str(random.randint(100, 999)),
        
        # Add padding pattern
        f"#{password}#123",
        
        # Make first letter capital and add number + special
        password[0].upper() + password[1:] + str(random.randint(10, 99)) + random.choice("!@#$%")
    ]
    
    logger.info(f"{Colors.GOOD} Original password: {password}")
    logger.info(f"   MD5: {original_md5}")
    logger.info(f"   SHA1: {original_sha1}")
    logger.info(f"\n{Colors.GOOD} Suggested stronger passwords:")
    
    for i, suggestion in enumerate(suggestions, 1):
        md5_hash = generate_password_hash(suggestion, 'md5')
        sha1_hash = generate_password_hash(suggestion, 'sha1')
        
        logger.info(f"  {i}. {suggestion}")
        logger.info(f"     MD5: {md5_hash}")
        logger.info(f"     SHA1: {sha1_hash}")
        
        # Show password strength assessment
        strength = 0
        if len(suggestion) >= 8: strength += 1
        if re.search(r'[A-Z]', suggestion): strength += 1
        if re.search(r'[a-z]', suggestion): strength += 1
        if re.search(r'[0-9]', suggestion): strength += 1
        if re.search(r'[^A-Za-z0-9]', suggestion): strength += 1
        
        strength_rating = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(strength, 4)]
        logger.info(f"     Strength: {strength_rating}\n")

# Main execution
def main():
    logger.info("Hash Cracker Tool Starting")
    
    if args.strongpass:
        suggest_strong_password(args.strongpass)
    elif args.dir:
        hashes = grepper(args.dir)
        if hashes and input("Do you want to attempt cracking the found hashes? (y/n): ").lower() == 'y':
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                executor.map(threaded, hashes)
    elif args.file:
        miner(args.file)
    elif args.hash:
        single(args.hash)
    else:
        logger.info(f"{Colors.INFO} No action specified. Use -s for single hash, -f for file, -d for directory, or -sp for password suggestions.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        logger.info("Hash Cracker Tool Finished")