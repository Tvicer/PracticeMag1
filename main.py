from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import asyncpg
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

API_V1_VERSION = "/api/v1"

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = "postgresql://postgres:123@localhost/pracDb"


async def init_db():
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL,
            file_content BYTEA NOT NULL
        )
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL
        )
    ''')
    await conn.close()


async def create_master_user():
    conn = await asyncpg.connect(DATABASE_URL)
    user = await conn.fetchrow('SELECT username FROM users WHERE username = $1', "admin")
    if not user:
        hashed_password = pwd_context.hash("admin")
        await conn.execute('INSERT INTO users (username, hashed_password) VALUES ($1, $2)', "admin", hashed_password)
    await conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await create_master_user()
    yield
    pass


app = FastAPI(lifespan=lifespan)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class LoginRequest(BaseModel):
    username: str
    password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_user(username: str):
    conn = await asyncpg.connect(DATABASE_URL)
    user_record = await conn.fetchrow('SELECT username, hashed_password FROM users WHERE username = $1', username)
    await conn.close()
    if user_record:
        return {"username": user_record['username'], "hashed_password": user_record['hashed_password']}


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(username)
    if user is None:
        raise credentials_exception
    return user


@app.post(API_V1_VERSION + "/token")
async def login(login_request: LoginRequest):
    user = await authenticate_user(login_request.username, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get(API_V1_VERSION + "/files")
async def list_files(current_user: dict = Depends(get_current_user)):
    conn = await asyncpg.connect(DATABASE_URL)
    files = await conn.fetch('SELECT filename FROM files')
    await conn.close()
    return {"files": [file['filename'] for file in files]}


@app.get(API_V1_VERSION + "/files/{filename}")
async def get_file_by_name(filename: str, current_user: dict = Depends(get_current_user)):
    conn = await asyncpg.connect(DATABASE_URL)
    file_record = await conn.fetchrow('SELECT filename, file_content FROM files WHERE filename = $1', filename)
    await conn.close()
    if file_record:
        filename, file_content = file_record['filename'], file_record['file_content']
        return StreamingResponse(
            iter([file_content]),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    else:
        raise HTTPException(status_code=404, detail="File not found")


@app.post(API_V1_VERSION + "/uploadfile")
async def create_upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    file_content = await file.read()
    conn = await asyncpg.connect(DATABASE_URL)

    existing_file = await conn.fetchrow('SELECT id FROM files WHERE filename = $1', file.filename)

    if existing_file:
        await conn.execute('''
            UPDATE files
            SET file_content = $1
            WHERE id = $2
        ''', file_content, existing_file['id'])
        message = "File updated successfully"
    else:
        await conn.execute('''
            INSERT INTO files (filename, file_content)
            VALUES ($1, $2)
        ''', file.filename, file_content)
        message = "File uploaded successfully"

    await conn.close()
    return {"filename": file.filename, "message": message}
