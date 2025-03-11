from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum

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


class Role(str, Enum):
    USER = "user"
    BANK_WORKER = "bank_worker"
    ADMIN = "admin"


async def init_db():
    conn = await asyncpg.connect(DATABASE_URL)
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS abs_files (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL,
            file_content BYTEA NOT NULL
        )
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS dbo_files (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL,
            file_content BYTEA NOT NULL
        )
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS contracts (
            id SERIAL PRIMARY KEY,
            contract_name TEXT NOT NULL UNIQUE
        )
    ''')
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS contract_files (
            contract_id INT REFERENCES contracts(id) ON DELETE CASCADE,
            file_id INT REFERENCES abs_files(id) ON DELETE CASCADE,
            PRIMARY KEY (contract_id, file_id)
        )
    ''')
    await conn.close()


async def create_master_user():
    conn = await asyncpg.connect(DATABASE_URL)

    admin = await conn.fetchrow('SELECT username FROM users WHERE username = $1', "admin")
    if not admin:
        hashed_password = pwd_context.hash("admin")
        await conn.execute('INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)',
                           "admin", hashed_password, Role.ADMIN)

    user = await conn.fetchrow('SELECT username FROM users WHERE username = $1', "user")
    if not user:
        hashed_password = pwd_context.hash("user")
        await conn.execute('INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)',
                           "user", hashed_password, Role.USER)

    bank_worker = await conn.fetchrow('SELECT username FROM users WHERE username = $1', "bank_worker")
    if not bank_worker:
        hashed_password = pwd_context.hash("bank_worker")
        await conn.execute('INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)',
                           "bank_worker", hashed_password, Role.BANK_WORKER)

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


class CreateContractRequest(BaseModel):
    contract_name: str


class LinkContractFileRequest(BaseModel):
    contract_name: str
    filename: str


class RegisterRequest(BaseModel):
    username: str
    password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_user(username: str):
    conn = await asyncpg.connect(DATABASE_URL)
    user_record = await conn.fetchrow('SELECT username, hashed_password, role FROM users WHERE username = $1', username)
    await conn.close()
    if user_record:
        return {
            "username": user_record['username'],
            "hashed_password": user_record['hashed_password'],
            "role": user_record['role']
        }


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


def check_role(current_user: dict, allowed_roles: list[Role]):
    if current_user["role"] not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource",
        )


@app.post(API_V1_VERSION + "/register")
async def register_user(register_request: RegisterRequest):
    conn = await asyncpg.connect(DATABASE_URL)

    existing_user = await conn.fetchrow('SELECT username FROM users WHERE username = $1', register_request.username)
    if existing_user:
        await conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(register_request.password)

    await conn.execute('''
        INSERT INTO users (username, hashed_password, role)
        VALUES ($1, $2, $3)
    ''', register_request.username, hashed_password, Role.USER)

    await conn.close()
    return {"message": "User registered successfully"}


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


@app.get(API_V1_VERSION + "/dbo/files")
async def list_dbo_files(current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.USER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    files = await conn.fetch('SELECT filename FROM dbo_files')
    await conn.close()
    return {"files": [file['filename'] for file in files]}


@app.get(API_V1_VERSION + "/dbo/files/{filename}")
async def get_dbo_file_by_name(filename: str, current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.USER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    file_record = await conn.fetchrow('SELECT filename, file_content FROM dbo_files WHERE filename = $1', filename)
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


@app.post(API_V1_VERSION + "/dbo/uploadfile")
async def create_upload_dbo_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.USER, Role.ADMIN])
    file_content = await file.read()
    conn = await asyncpg.connect(DATABASE_URL)

    existing_file = await conn.fetchrow('SELECT id FROM dbo_files WHERE filename = $1', file.filename)

    if existing_file:

        await conn.execute('''
            UPDATE dbo_files
            SET file_content = $1
            WHERE id = $2
        ''', file_content, existing_file['id'])
        message = "File updated successfully"
    else:

        await conn.execute('''
            INSERT INTO dbo_files (filename, file_content)
            VALUES ($1, $2)
        ''', file.filename, file_content)
        message = "File uploaded successfully"

    await conn.close()
    return {"filename": file.filename, "message": message}


@app.get(API_V1_VERSION + "/abs/files")
async def list_abs_files(current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.BANK_WORKER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    files = await conn.fetch('SELECT filename FROM abs_files')
    await conn.close()
    return {"files": [file['filename'] for file in files]}


@app.get(API_V1_VERSION + "/abs/files/{filename}")
async def get_abs_file_by_name(filename: str, current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.BANK_WORKER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    file_record = await conn.fetchrow('SELECT filename, file_content FROM abs_files WHERE filename = $1', filename)
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


@app.post(API_V1_VERSION + "/abs/uploadfile")
async def create_upload_abs_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.BANK_WORKER, Role.ADMIN])
    file_content = await file.read()
    conn = await asyncpg.connect(DATABASE_URL)

    existing_file = await conn.fetchrow('SELECT id FROM abs_files WHERE filename = $1', file.filename)

    if existing_file:

        await conn.execute('''
            UPDATE abs_files
            SET file_content = $1
            WHERE id = $2
        ''', file_content, existing_file['id'])
        message = "File updated successfully"
    else:
        await conn.execute('''
            INSERT INTO abs_files (filename, file_content)
            VALUES ($1, $2)
        ''', file.filename, file_content)
        message = "File uploaded successfully"

    await conn.close()
    return {"filename": file.filename, "message": message}


@app.post(API_V1_VERSION + "/sm/create_contract")
async def create_contract(contract_request: CreateContractRequest, current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.BANK_WORKER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute('''
            INSERT INTO contracts (contract_name)
            VALUES ($1)
        ''', contract_request.contract_name)
        return {"message": "Contract created successfully"}
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=400, detail="Contract with this name already exists")
    finally:
        await conn.close()


@app.post(API_V1_VERSION + "/sm/link")
async def link_contract_file(link_request: LinkContractFileRequest, current_user: dict = Depends(get_current_user)):
    check_role(current_user, [Role.BANK_WORKER, Role.ADMIN])
    conn = await asyncpg.connect(DATABASE_URL)
    try:

        contract = await conn.fetchrow('SELECT id FROM contracts WHERE contract_name = $1', link_request.contract_name)
        if not contract:
            raise HTTPException(status_code=404, detail="Contract not found")

        file = await conn.fetchrow('SELECT id FROM abs_files WHERE filename = $1', link_request.filename)
        if not file:
            raise HTTPException(status_code=404, detail="File not found")

        existing_link = await conn.fetchrow('''
            SELECT contract_id, file_id 
            FROM contract_files 
            WHERE contract_id = $1 AND file_id = $2
        ''', contract['id'], file['id'])

        if existing_link:
            return {"message": "The link between the contract and the file already exists"}

        await conn.execute('''
            INSERT INTO contract_files (contract_id, file_id)
            VALUES ($1, $2)
        ''', contract['id'], file['id'])

        return {"message": "Contract and file linked successfully"}
    finally:
        await conn.close()
