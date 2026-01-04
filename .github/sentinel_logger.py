import json
import requests
import datetime
import hashlib
import hmac
import base64
import os
import sys

# Update these with your workspace ID and primary key from the secrets
customer_id = os.environ.get('SENTINEL_WORKSPACE_ID')
shared_key = os.environ.get('SENTINEL_SHARED_KEY')
log_type = 'USDValidationLogs'

def build_signature(date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

def post_data(body):
    if not customer_id or not shared_key:
        print("Sentinel credentials not found in environment variables. Skipping logging.")
        return

    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    try:
        response = requests.post(uri, data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            print('Logged to Sentinel successfully')
        else:
            print("Error logging to Sentinel. Response code: {}. Response: {}".format(response.status_code, response.text))
    except requests.exceptions.RequestException as e:
        print("Exception logging to Sentinel: {}".format(str(e)))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: sentinel_logger.py <status> <message> [file_path]")
        sys.exit(1)
        
    status = sys.argv[1]
    message = sys.argv[2]
    file_path = sys.argv[3] if len(sys.argv) > 3 else "N/A"
    
    data = [{
        "Status": status,
        "Message": message,
        "FilePath": file_path,
        "Repo": os.environ.get('GITHUB_REPOSITORY', 'unknown'),
        "RunId": os.environ.get('GITHUB_RUN_ID', 'unknown'),
        "Timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    }]
    
    body = json.dumps(data)
    post_data(body)
