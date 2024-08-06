from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from datetime import datetime, timedelta
from pymongo import MongoClient

import os
import tempfile
import json

username = os.getenv("MONGO_USERNAME")
password = os.getenv("MONGO_PASSWORD")
cluster_name = os.getenv("MONGO_CLUSTER_NAME")
cluster_address = os.getenv("MONGO_CLUSTER_ADDRESS")

mongodb_uri = f"mongodb+srv://{username}:{password}@{cluster_address}/?retryWrites=true&w=majority&appName={cluster_name}"
port = 8000

client = MongoClient(mongodb_uri, port)

db = client["collection"]
tokens_collection = db["gauthtoken"]

SECRET_KEY = os.getenv("SECRET_KEY")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
SCOPES = ['https://www.googleapis.com/auth/drive']
REDIRECT_URI = "http://localhost:8000/oauth2callback"
CLIENT_SECRETS_FILE = "credentials.json"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 360

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Hash():
    def bcrypt(password: str):
        return pwd_cxt.hash(password)
    
    def verify(hashed, normal):
        return pwd_cxt.verify(normal, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        print(payload)
        return payload
    except JWTError:
        raise credentials_exception
    
def get_current_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
	return verify_token(token,credentials_exception)

app = FastAPI(
    title="Login",
    swagger_ui_parameters={"syntaxHighlight": False}
    )

flow = Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE,
    scopes=SCOPES,
    redirect_uri=REDIRECT_URI
)

class UserToken(BaseModel):
    user_id: str
    token: dict

@app.get("/authorize/{user_id}")
async def authorize(user_id: str):
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        state=user_id
    )
    print(authorization_url)
    return RedirectResponse(authorization_url)

# Endpoint to handle the OAuth 2.0 callback and exchange code for tokens
@app.get("/oauth2callback")
async def oauth2callback(request: Request):
    user_id = request.query_params.get('state')
    flow.fetch_token(authorization_response=str(request.url))

    if not flow.credentials:
        raise HTTPException(status_code=400, detail="Authorization failed.")

    credentials = flow.credentials
    token_data = {
        "token": credentials.to_json()
    }

    # Save the token in MongoDB
    tokens_collection.update_one(
        {"user_id": user_id},
        {"$set": token_data},
        upsert=True
    )

    return {"message": "Authorization successful!"}

# Function to get authenticated Google Drive service
async def get_drive_service(user_id: str):
    user_token = tokens_collection.find_one({"user_id": user_id})
    if not user_token:
        raise HTTPException(status_code=401, detail="Credentials are invalid or missing.")

    credentials = Credentials.from_authorized_user_info(json.loads(user_token['token']), SCOPES)

    if not credentials or not credentials.valid:
        raise HTTPException(status_code=401, detail="Credentials are invalid or missing.")

    service = build('drive', 'v3', credentials=credentials)
    return service

# Example endpoint to list files in Google Drive
@app.get("/list_files")
async def list_files(current_user: dict = Depends(get_current_user), 
                     page_size: int = Query(10, gt=0), 
                     page_token: Optional[str] = Query(None)):
    user_id = current_user.get("sub")
    service = await get_drive_service(user_id)

    # Construct query to filter PDF and DOCX files
    query = "mimeType='application/pdf' or mimeType='application/vnd.openxmlformats-officedocument.wordprocessingml.document'"

    # Execute files list request with the constructed query
    results = service.files().list(q=query, pageSize=page_size, pageToken=page_token, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])
    next_page_token = results.get('nextPageToken')
    return {"files": items, "next_page_token": next_page_token}

@app.get("/download_file/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("sub")
    service = await get_drive_service(user_id)

    # Get file metadata
    file_metadata = service.files().get(fileId=file_id, fields="name, mimeType").execute()
    file_name = file_metadata.get('name')
    if not file_name:
        raise HTTPException(status_code=404, detail="File not found.")

    # Get file extension from MIME type
    file_extension = file_metadata.get('mimeType').split("/")[-1]

    # Download file content
    request = service.files().get_media(fileId=file_id)
    with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as tmp_file:
        # Download file content and write to temporary file
        downloader = MediaIoBaseDownload(tmp_file, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

    response = {"filepath" : tmp_file.name}
    #os.remove(tmp_file.name)
    return response
