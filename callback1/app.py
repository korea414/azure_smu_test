import os
import hashlib
import base64
import requests
from flask import Flask, redirect, request, session, url_for
from urllib.parse import urlencode
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI')
AUTHORITY = 'https://login.microsoftonline.com/ea44faef-f5d3-4ff6-9a3b-75002d755298'
AUTHORIZE_URL = f'{AUTHORITY}/oauth2/v2.0/authorize'
TOKEN_URL = f'{AUTHORITY}/oauth2/v2.0/token'
SCOPE = ['openid', 'profile', 'email']

@app.route('/')
def index():
    return 'Welcome to the Microsoft Entra ID integration example'

@app.route('/login')
def login():
    code_verifier = secrets.token_urlsafe(128)
    session['code_verifier'] = code_verifier

    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')

    auth_params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'response_mode': 'query',
        'scope': ' '.join(SCOPE),
        'state': 'random_state',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    auth_url = f'{AUTHORIZE_URL}?{urlencode(auth_params)}'
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')

    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }
    response = requests.post(TOKEN_URL, data=token_data)
    token_json = response.json()

    session['access_token'] = token_json.get('access_token')

    return 'Authentication successful. You can now make API calls.'

@app.route('/profile')
def profile():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login'))

    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
    profile_info = response.json()

    return f"User Profile: {profile_info}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
