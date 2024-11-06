import hmac
import hashlib
import json
from flask import Flask, request, abort
import subprocess
import argparse

app = Flask(__name__)
configpath = './config.json'

def verify_signature(req, secret):
    signature = req.headers.get('X-Hub-Signature-256')
    if not signature:
        abort(400, 'Missing signature')

    digest = hmac.new(secret.encode(), req.data, hashlib.sha256).hexdigest()
    expected_signature = f'sha256={digest}'

    if not hmac.compare_digest(signature, expected_signature):
        abort(403, 'Invalid signature')

@app.route('/github-webhook/<id>', methods=['POST'])
def github_webhook(id):
    try:
        with open(configpath, 'r') as config_file:
            config = json.load(config_file)
    except (json.JSONDecodeError, IOError) as e:
        print(f'Error reading config file: {e}')
        abort(500, 'Internal server error')

    if id not in config:
        abort(404, f'No configuration found for id: {id}')

    branch = config[id].get('branch')
    script = config[id].get('script')
    secret = config[id].get('secret')
    push_branch = request.json.get('ref')

    verify_signature(request, secret)

    if branch == '-' or push_branch == branch:
        try:
            result = subprocess.run(script, shell=True, check=True, capture_output=True, text=True)
            print(f'stdout: {result.stdout}')
            return 'Script executed successfully', 200
        except subprocess.CalledProcessError as e:
            print(f'Error: {e.stderr}')
            abort(500, 'Script execution failed')
    else:
        return 'Not the target branch', 200

def main():
    parser = argparse.ArgumentParser(description='Osiris v0.1 - GitHub webhook receiver')
    parser.add_argument('-p', type=int, default=21010, help='Port to run the server on')
    parser.add_argument('-c', type=str, default='./config.json', help='Path to the configuration file')
    args = parser.parse_args()

    print('Osiris v0.1 - GitHub webhook receiver')

    configpath = args.c
    app.run(port=args.p)

if __name__ == '__main__':
    main()

