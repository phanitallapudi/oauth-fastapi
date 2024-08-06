from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import JSONResponse

import os
import requests
import httpx

load_dotenv()

oauth = OAuth()

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI")

oauth.register(
    "linkedin",
    client_id=LINKEDIN_CLIENT_ID,
    client_secret=LINKEDIN_CLIENT_SECRET,
    api_base_url='https://api.linkedin.com/v2/',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    client_kwargs={'scope': 'openid profile email'}, 
)

def get_linkedin_userinfo(access_token):
    url = "https://api.linkedin.com/v2/userinfo"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


app = FastAPI(
    title="Login",
    swagger_ui_parameters={"syntaxHighlight": False}
    )

allowed_origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY'))  

@app.get("/login/linkedin")
async def linkedin_login(request: Request):
    linkedin = oauth.create_client('linkedin')
    if linkedin:
        print(linkedin.name)
        redirect_uri = request.url_for('linkedin_auth')
        print(redirect_uri)
        return await linkedin.authorize_redirect(request, redirect_uri)
    else:
        return {'error': 'linkedin client not found'}

@app.get("/callback/linkedin")
async def linkedin_auth(code: str):
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization code not found")

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": LINKEDIN_REDIRECT_URI,
                "client_id": LINKEDIN_CLIENT_ID,
                "client_secret": LINKEDIN_CLIENT_SECRET,
            },
        )
        token_response_data = token_response.json()
        access_token = token_response_data.get("access_token")
        userInfo = get_linkedin_userinfo(access_token=access_token)

        return JSONResponse(content=userInfo, status_code=status.HTTP_200_OK)
