
Hash Cracking Tool
<h1 align="center"> <br> Hash Cracking Tool <br> </h1> <h4 align="center">A web-based application for cracking cryptographic hashes and suggesting stronger password alternatives</h4> <p align="center"> <a href="https://github.com/Dineshh9515/Hash-Cracking-Tool"> <img src="https://img.shields.io/badge/version-1.0-blue.svg"> </a> </p>
Features
Automatic hash type identification

Supports multiple hash types: MD5, SHA1, SHA256, SHA384, SHA512

Single hash cracking

Batch processing of multiple hashes

File upload for extracting and cracking hashes

Folder processing for finding hashes in multiple files

Password strengthening suggestions

Multi-threading for efficient processing

Installation
Prerequisites
Python 3.6 or higher

pip (Python package installer)

Setup
Clone the repository or download the source code:

text
git clone https://github.com/Dineshh9515/Hash-Cracking-Tool
cd Hash-Cracking-Tool
Install required dependencies:

text
pip install flask requests urllib3
Run the application:

text
python app.py
Open your web browser and navigate to:

text
http://127.0.0.1:5000
Usage
Single Hash Cracking
Enter a hash value in the input field

Select the hash type (or let the tool auto-detect based on length)

Click "Crack Hash"

View the result below the form

Batch Processing
Click the "Upload File" tab

Select a text file containing hashes (one per line)

Click "Upload and Crack"

View the results in the table

Folder Processing
Click the "Upload Folder" tab

Select multiple files from a folder

Click "Upload and Process"

View the results grouped by file

Password Strengthening
Click the "Password Suggestions" tab

Enter a password

Click "Get Suggestions"

View the suggested stronger alternatives

API Services
The tool uses the following services to attempt hash cracking:

cmd5.org

nitrxgen.net (MD5 only)

md5decrypt.net

Note: These services may have usage limitations or require registration.

Troubleshooting
If the application fails to start, ensure all dependencies are installed

If hash cracking is unsuccessful, try a different hash type or check the hash format

If file upload fails, ensure the file is a text file with valid hash values

Internet connection is required for the tool to access online cracking services

License
This project is licensed under the MIT License.

Author
Dineshh9515