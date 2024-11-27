import os
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import ActiveToken, User
from jwt.exceptions import InvalidTokenError
import logging

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "oaWndjh2348fg@#dDFYRTJ2@31") 
ALGORITHM = "HS256"  
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """
    Hash the user's password using bcrypt.
    This function is used to securely store the password in the database.
    """
    try:
        # Using bcrypt for hashing the password
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise RuntimeError("Error hashing password.")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify the plain password against the hashed password.
    This function is used to authenticate the user during login.
    """
    try:
        # Verifying if the plain password matches the hashed one
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        raise RuntimeError("Error verifying password.")

async def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Generate a JWT access token with an expiration time.
    This function is used to create tokens for authenticated users after successful login or signup.
    """
    try:
        # Copy the data and add an expiration time to the payload
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})  # Set expiration time for the token

        # Generate the JWT token using the secret key and algorithm
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise RuntimeError("Error creating access token.")

async def decode_token(active_token: str):
    """
    Decode the JWT token and return the payload.
    This function is used to decode and verify the token when performing operations like token refresh.
    """
    try:
        # Decode the JWT token using the secret key and algorithm
        payload = jwt.decode(active_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired.")
        raise RuntimeError("Token has expired.")  # Raise an error if the token has expired
    except jwt.InvalidTokenError:
        logger.warning("Invalid token.")
        raise RuntimeError("Invalid token.")  # Raise an error if the token is invalid
    except Exception as e:
        logger.error(f"Error decoding token: {e}")
        raise RuntimeError("Error decoding token.")


async def save_new_user(db: AsyncSession, user) -> int:
    """
    Save a new user to the database after hashing the password.
    This function is used during the signup process to create a new user account.
    """
    try:
        # Create a new user object with the email and hashed password
        new_user = User(email=user.email, hashed_password=hash_password(user.password))

        # Add the new user to the session and commit the transaction
        db.add(new_user)
        db.commit()
        db.refresh(new_user)  # Refresh the session to get the new user's id

        return new_user.id  # Return the user's id after successful creation
    except Exception as e:
        logger.error(f"Error saving new user: {e}")
        db.rollback()  # Rollback any changes in case of error
        raise RuntimeError("Error saving new user.")

async def check_user(db: AsyncSession, email: str):
    """
    Check if a user with the given email exists in the database.
    This function is used during both signup and login to verify if a user exists.
    """
    try:
        # Execute a query to find the user by email
        result = db.execute(select(User).filter(User.email == email))
        return result.scalar_one_or_none()  # Return the user if found, otherwise None
    except Exception as e:
        logger.error(f"Error checking user: {e}")
        raise RuntimeError("Error checking user.")

async def check_db_connection(db: AsyncSession) -> bool:
    """
    Check if the database connection is alive and working.
    This function is used for health checks to verify the system's integrity.
    """
    try:
        # Execute a simple query to test the database connection
        result = db.execute(select(1))
        return result.scalars().first() is not None  # Return True if the connection is valid
    except Exception as e:
        logger.error(f"Error checking database connection: {e}")
        raise RuntimeError("Error checking database connection.")


async def save_active_token(db: AsyncSession, user_id: int, active_token: str):
    """
    Save or update the active token for a given user.
    This function is used to track the current active token associated with the user.
    """
    try:
        # Check if the user already has an active token
        result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        db_token = result.scalar_one_or_none()

        if db_token:
            # If the token already exists, update it with the new token
            db_token.active_token = active_token
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the updated token
        else:
            # If no active token exists, create a new active token
            db_token = ActiveToken(active_token=active_token, user_id=user_id)
            db.add(db_token)
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the new active token
    except Exception as e:
        logger.error(f"Error saving active token: {e}")
        db.rollback()  # Ensure to rollback the transaction if there is an error
        raise RuntimeError("Error saving active token.")

async def check_active_token(
    db: AsyncSession, user_id: int = None, active_token: str = None
) -> ActiveToken | None:
    """
    Check if an active token exists for a given user or token.
    This function verifies whether the provided token is still valid and active.
    """
    if not user_id and not active_token:
        raise InvalidTokenError("Either user_id or active_token must be provided.")  # Must provide either user_id or active_token

    try:
        # Query for active token either by user_id or active_token
        if user_id:
            result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        elif active_token:
            result = db.execute(select(ActiveToken).filter(ActiveToken.active_token == active_token))

        db_token = result.scalar_one_or_none()

        if not db_token:
            raise InvalidTokenError("No active token found for the provided input.")  # If no active token is found, raise an error

        return db_token  # Return the found active token
    except InvalidTokenError as e:
        logger.warning(f"Invalid token error: {e}")
        raise e  # Raise the InvalidTokenError
    except Exception as e:
        logger.error(f"Error checking active token: {e}")
        raise RuntimeError("Unexpected error while checking active token.")  # Raise a general runtime error for unexpected issues


async def delete_active_token(db: AsyncSession, user_id: int = None, active_token: str = None) -> bool:
    """
    Delete an active token based on user_id or active_token.
    This function ensures that any active token is properly revoked when the user logs out or refreshes the token.
    """
    if not user_id and not active_token:
        raise RuntimeError("Either user_id or active_token must be provided.")  # Must provide either user_id or active_token

    try:
        # Determine the query based on the provided user_id or active_token
        query = None
        if user_id:
            query = select(ActiveToken).filter(ActiveToken.user_id == user_id)
        elif active_token:
            query = select(ActiveToken).filter(ActiveToken.active_token == active_token)
        
        result = db.execute(query)
        db_token = result.scalar_one_or_none()

        if db_token:
            # If token exists, delete it
            db.delete(db_token)
            db.commit()
            return True  # Return True indicating successful deletion

        # If no token was found, just return True (no token to delete)
        return True
    except Exception as e:
        logger.error(f"Error deleting active token: {e}")
        db.rollback()  # Rollback the transaction if any error occurs
        raise RuntimeError("Error deleting active token.")  # Raise error for issues during deletion
