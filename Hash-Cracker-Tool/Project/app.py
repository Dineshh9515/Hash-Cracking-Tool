from flask import Flask, request, jsonify, render_template
import os
import re
import requests
import concurrent.futures
import urllib3
import random
import string
import json
import tempfile

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Hash cracking functions from hash.py
def alpha(hashvalue, hashtype):
    """ Uses cmd5.org for hash cracking. """
    try:
        response = requests.post(
            'https://www.cmd5.org/',
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            data={
                '__EVENTTARGET': 'Button1',
                'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
                'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
                'ctl00$ContentPlaceHolder1$Button1': 'decrypt'
            },
            timeout=10
        )
        match = re.search(r'<span id="LabelAnswer"[^>]+?>(.+)</span>', response.text)
        return match.group(1).strip() if match else False
    except requests.RequestException:
        return False

def beta(hashvalue, hashtype):
    """ Simulated API call - for demo purposes """
    try:
        # This is a simplified version to avoid WebSocket complexity
        # In a real implementation, you would use the WebSocket code from hash.py
        return False
    except Exception:
        return False

def gamma(hashvalue, hashtype):
    """ Uses nitrxgen.net for MD5 cracking. """
    if hashtype != 'md5':
        return False
        
    try:
        response = requests.get(
            f'https://www.nitrxgen.net/md5db/{hashvalue}', 
            timeout=10, 
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        )
        return response.text.strip() if response.text else False
    except requests.RequestException:
        return False

def theta(hashvalue, hashtype):
    """ Uses md5decrypt.net API (requires an email and API key). """
    try:
        url = f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6'
        response = requests.get(
            url, 
            timeout=10,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        )
        return response.text.strip() if response.text and response.text != 'ERROR CODE : 001' else False
    except requests.RequestException:
        return False

hash_methods = {
    32: ['md5', [alpha, beta, gamma, theta]],
    40: ['sha1', [alpha, beta, theta]],
    64: ['sha256', [alpha, beta, theta]],
    96: ['sha384', [alpha, beta, theta]],
    128: ['sha512', [alpha, beta, theta]]
}

def crack(hashvalue):
    """ Determines hash type and attempts to crack it. """
    length = len(hashvalue)
    if length in hash_methods:
        hashtype, apis = hash_methods[length]
        for api in apis:
            result = api(hashvalue, hashtype)
            if result:
                return result
        return False
    return False

def threaded_crack(hashvalue):
    """ Threaded hash cracking. """
    return crack(hashvalue)

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crack', methods=['POST'])
def crack_hash():
    data = request.json
    
    if data['type'] == 'single':
        hash_value = data['hash']
        result = crack(hash_value)
        return jsonify({'result': result})
    
    elif data['type'] == 'multiple':
        hashes = data['hashes']
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_hash = {executor.submit(threaded_crack, hash_value): hash_value for hash_value in hashes}
            for future in concurrent.futures.as_completed(future_to_hash):
                hash_value = future_to_hash[future]
                try:
                    result = future.result()
                    results[hash_value] = result
                except Exception:
                    results[hash_value] = None
        
        return jsonify({'results': results})

@app.route('/upload-file', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # Save the file temporarily
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    file.save(temp_file.name)
    
    # Process the file
    hashes = set()
    with open(temp_file.name, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            hashes.update(re.findall(r'[a-f0-9]{32,128}', line.strip()))
    
    # Clean up
    temp_file.close()
    os.unlink(temp_file.name)
    
    # Crack the hashes
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_hash = {executor.submit(threaded_crack, hash_value): hash_value for hash_value in hashes}
        for future in concurrent.futures.as_completed(future_to_hash):
            hash_value = future_to_hash[future]
            try:
                result = future.result()
                results[hash_value] = result
            except Exception:
                results[hash_value] = None
    
    return jsonify({'results': results})

@app.route('/upload-folder', methods=['POST'])
def upload_folder():
    files = request.files.getlist('files')
    paths = request.form.getlist('paths')
    
    all_results = {}
    
    for i, file in enumerate(files):
        # Save the file temporarily
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file.save(temp_file.name)
        
        # Process the file
        hashes = set()
        with open(temp_file.name, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                hashes.update(re.findall(r'[a-f0-9]{32,128}', line.strip()))
        
        # Clean up
        temp_file.close()
        os.unlink(temp_file.name)
        
        # Crack the hashes
        file_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_hash = {executor.submit(threaded_crack, hash_value): hash_value for hash_value in hashes}
            for future in concurrent.futures.as_completed(future_to_hash):
                hash_value = future_to_hash[future]
                try:
                    result = future.result()
                    file_results[hash_value] = result
                except Exception:
                    file_results[hash_value] = None
        
        if file_results:
            all_results[paths[i]] = file_results
    
    return jsonify({'results': all_results})

@app.route('/suggest', methods=['POST'])
def suggest_password():
    data = request.json
    password = data['password']
    
    suggestions = []
    
    # Insert uppercase letter in the middle
    suggestions.append(password[:len(password)//2] + random.choice(string.ascii_uppercase) + password[len(password)//2:])
    
    # Add special character
    suggestions.append(password + random.choice("!@#$%^&*"))
    
    # Replace common letters with symbols
    suggestions.append(password.replace('a', '@').replace('i', '1').replace('e', '3'))
    
    # Reverse + number
    suggestions.append(password[::-1] + str(random.randint(0, 9)))
    
    # Mix of strategies
    mixed = ''.join(random.choice([c.upper(), c.lower()]) for c in password)
    suggestions.append(mixed + random.choice("!@#$%^&*") + str(random.randint(0, 99)))
    
    return jsonify({'suggestions': suggestions})

if __name__ == '__main__':
    app.run(debug=True)