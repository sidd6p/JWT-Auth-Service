import os
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import ActiveToken, User
from sqlalchemy.future import select
from app.models import User

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "oaWndjh2348fg@#dDFYRTJ2@31")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def decode_token(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload


async def save_new_user(db: AsyncSession, user):
    new_user = User(email=user.email, hashed_password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)


async def check_user(db: AsyncSession , email):
    result = db.execute(select(User).filter(User.email == email))
    db_user = result.scalar_one_or_none()  
    return db_user


async def check_db_connection(db):
    result = db.execute(select(1))  
    result_value = result.scalars().first()
    return result_value


async def save_active_token(db: AsyncSession, user: str, token: str):
    result = await db.execute(select(ActiveToken).filter(ActiveToken.user == user))
    db_token = result.scalar_one_or_none()

    if db_token:
        db_token.token = token
        await db.commit()
        return db_token
    else:
        db_token = ActiveToken(token=token, user=user)
        db.add(db_token)
        await db.commit()
        return db_token

async def check_active_token(db: AsyncSession, user: str):
    result = await db.execute(select(ActiveToken).filter(ActiveToken.user == user))
    db_token = result.scalar_one_or_none()

    if db_token:
        return db_token
    else:
        return False

async def delete_active_token(db: AsyncSession, user: str = None, token: str = None):
    if user:
        result = await db.execute(select(ActiveToken).filter(ActiveToken.user == user))
        db_token = result.scalar_one_or_none()
    elif token:
        result = await db.execute(select(ActiveToken).filter(ActiveToken.token == token))
        db_token = result.scalar_one_or_none()
    else:
        return False

    if db_token:
        await db.delete(db_token)
        await db.commit()
        return True
    else:
        return False
