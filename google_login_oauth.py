from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

import os

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'

google_oauth = OAuth()

google_oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY'))  

@app.get('/login/google')
async def google_login(request: Request):
    redirect_uri = request.url_for('google_auth_redirect_function')
    return await google_oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/callback/google")
async def google_auth_redirect_function(request: Request):
    try:
        token = await google_oauth.google.authorize_access_token(request)
        userInfo = token.get('userinfo')
        return userInfo
    except OAuthError as error:
        return error
