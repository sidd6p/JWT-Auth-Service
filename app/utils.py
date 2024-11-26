import os
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import ActiveToken, User
from jwt.exceptions import InvalidTokenError

# Load environment variables
load_dotenv()

# Configurations
SECRET_KEY = os.getenv("SECRET_KEY", "oaWndjh2348fg@#dDFYRTJ2@31")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Password hashing and verification
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT token creation and decoding
async def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        raise RuntimeError(f"Error creating access token: {e}")

async def decode_token(active_token: str):
    try:
        payload = jwt.decode(active_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise RuntimeError("Token has expired")
    except jwt.InvalidTokenError as error:
        raise RuntimeError("Invalid token")

async def save_new_user(db: AsyncSession, user) -> int:
    try:
        new_user = User(email=user.email, hashed_password=hash_password(user.password))
        
        db.add(new_user)
        db.commit()  
        db.refresh(new_user)  
        
        return new_user.id
    
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"Error saving new user: {e}")


async def check_user(db: AsyncSession, email: str):
    try:
        result = db.execute(select(User).filter(User.email == email))
        return result.scalar_one_or_none()
    except Exception as e:
        raise RuntimeError(f"Error checking user: {e}")

async def check_db_connection(db: AsyncSession) -> bool:
    try:
        result = db.execute(select(1))
        return result.scalars().first() is not None
    except Exception as e:
        raise RuntimeError(f"Error checking database connection: {e}")

async def save_active_token(db: AsyncSession, user_id: int, active_token: str):
    try:
        result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        db_token = result.scalar_one_or_none()

        if db_token:
            db_token.active_token = active_token
            db.commit()
            db.refresh(db_token)
            return db_token
        else:
            db_token = ActiveToken(active_token=active_token, user_id=user_id)
            db.add(db_token)
            db.commit()
            db.refresh(db_token)
            return db_token
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"Error saving active token: {e}")


async def check_active_token(db: AsyncSession, active_token: str):
    decoded = await decode_token(active_token)
    if "user_id" not in decoded or "exp" not in decoded:
        raise InvalidTokenError("Invalfid Token.")
    result = await db.execute(select(ActiveToken).filter(ActiveToken.user.user_id == decoded["user_id"]))
    db_token = result.scalar_one_or_none()
    
    if db_token:
        return None
    else:
        raise InvalidTokenError("No active token found for the provided user.")


async def delete_active_token(db: AsyncSession, user_id: int = None, active_token: str = None) -> bool:
    try:
        if user_id:
            result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        elif active_token:
            result = db.execute(select(ActiveToken).filter(ActiveToken.active_token == active_token))
        else:
            return False

        db_token = result.scalar_one_or_none()

        if db_token:
            db.delete(db_token)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        raise RuntimeError(f"Error deleting active token: {e}")
