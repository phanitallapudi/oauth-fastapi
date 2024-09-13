from fastapi import status, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_sso.sso.microsoft import MicrosoftSSO

import os

app = FastAPI()

MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")
MICROSOFT_TENANT = os.getenv("MICROSOFT_TENANT")
MICROSOFT_REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI")

sso = MicrosoftSSO(
    client_id=MICROSOFT_CLIENT_ID,
    client_secret=MICROSOFT_CLIENT_SECRET,
    tenant=MICROSOFT_TENANT,
    redirect_uri=MICROSOFT_REDIRECT_URI,
    allow_insecure_http=True,
)

    
@app.get("/login/microsoft")
async def microsoft_login():
    """Initialize auth and redirect"""
    with sso:
        return await sso.get_login_redirect()


@app.get("/callback/microsoft")
async def microsoft_auth_redirect_function(request: Request):
    with sso:
        response = await sso.verify_and_process(request)
    
    return JSONResponse(content=response, status_code=status.HTTP_200_OK)
