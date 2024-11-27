import os
import jwt
import logging

from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import ActiveToken, User
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from fastapi import HTTPException, status

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "oaWndjh2348fg@#dDFYRTJ2@31")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")],
)

logger = logging.getLogger(__name__)


# Helper function to log route and request time
def log_route(route: str, level: str, message: str):
    logger.log(level, f"Route: {route} - {message}")


def hash_password(password: str) -> str:
    """
    Hash the user's password using bcrypt.
    This function is used to securely store the password in the database.
    """
    try:
        logger.info("hash_password: Hashing the password")
        return pwd_context.hash(password)
    except ValueError as e:
        logger.error(f"hash_password: Value error while hashing password: {e}")
        raise ValueError("Error hashing password due to invalid value.")
    except TypeError as e:
        logger.error(f"hash_password: Type error while hashing password: {e}")
        raise TypeError("Error hashing password due to incorrect type.")
    except Exception as e:
        logger.error(f"hash_password: Error hashing password: {e}")
        raise RuntimeError("Error hashing password.")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify the plain password against the hashed password.
    This function is used to authenticate the user during login.
    """
    try:
        logger.info("verify_password: Verifying the password")
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError as e:
        logger.error(f"verify_password: Value error while verifying password: {e}")
        raise ValueError("Error verifying password due to invalid value.")
    except TypeError as e:
        logger.error(f"verify_password: Type error while verifying password: {e}")
        raise TypeError("Error verifying password due to incorrect type.")
    except Exception as e:
        logger.error(f"verify_password: Error verifying password: {e}")
        raise RuntimeError("Error verifying password.")


async def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Generate a JWT access token with an expiration time.
    This function is used to create tokens for authenticated users after successful login or signup.
    """
    try:
        logger.info("create_access_token: Creating JWT access token")
        to_encode = data.copy()
        expire = datetime.utcnow() + (
            expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": expire})  # Set expiration time for the token
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except jwt.ExpiredSignatureError as e:
        logger.error(f"create_access_token: JWT signature expired: {e}")
        raise jwt.ExpiredSignatureError("JWT signature has expired.")
    except jwt.InvalidTokenError as e:
        logger.error(f"create_access_token: Invalid JWT token: {e}")
        raise jwt.InvalidTokenError("Invalid JWT token.")
    except ValueError as e:
        logger.error(
            f"create_access_token: Value error while creating access token: {e}"
        )
        raise ValueError("Error with input data while creating access token.")
    except Exception as e:
        logger.error(f"create_access_token: Error creating access token: {e}")
        raise RuntimeError("Error creating access token.")


async def decode_token(active_token: str):
    """
    Decode the JWT token and return the payload.
    This function is used to decode and verify the token when performing operations like token refresh.
    """
    try:
        logger.info("decode_token: Decoding the JWT token")
        payload = jwt.decode(active_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("decode_token: Token has expired.")
        raise jwt.ExpiredSignatureError("Token has expired.")
    except jwt.InvalidTokenError:
        logger.warning("decode_token: Invalid token.")
        raise jwt.InvalidTokenError("Invalid token.")
    except Exception as e:
        logger.error(f"decode_token: Error decoding token: {e}")
        raise RuntimeError("Error decoding token.")


async def save_new_user(db: AsyncSession, user) -> int:
    """
    Hashes the user's password and saves the user in the database.
    Ensures that the email is unique and handles potential database errors.
    """
    try:
        logger.info(
            f"save_new_user: Attempting to save a new user with email {user.email}."
        )

        # Hash the user's password and create a new user object
        new_user = User(email=user.email, hashed_password=hash_password(user.password))

        # Add the user to the session
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(
            f"save_new_user: Successfully saved user with email {user.email} and ID {new_user.id}."
        )
        return new_user.id

    except IntegrityError as e:
        logger.error(
            f"save_new_user: Integrity error while saving user with email {user.email}: {e}"
        )
        db.rollback()
        raise IntegrityError(f"User with email {user.email} already exists.")
    except DatabaseError as e:
        logger.error(
            f"save_new_user: Database error while saving user with email {user.email}: {e}"
        )
        db.rollback()
        raise DatabaseError("Database error occurred while saving user.")
    except Exception as e:
        logger.error(
            f"save_new_user: Unexpected error while saving user with email {user.email}: {e}"
        )
        db.rollback()
        raise RuntimeError("Error saving new user.")


async def check_user(db: AsyncSession, email: str):
    """
    Verifies if a user with the specified email exists in the database.
    Used during both signup and signin to check for existing user accounts.
    """
    try:
        logger.info(f"check_user: Checking if user with email {email} exists.")

        # Query the database for a user with the given email
        result = db.execute(select(User).filter(User.email == email))

        # Return the user object if found, otherwise None
        return result.scalar_one_or_none()

    except NoResultFound as e:
        logger.error(f"check_user: User with email {email} not found: {e}")
        raise NoResultFound(f"User with email {email} does not exist.")

    except DatabaseError as e:
        logger.error(f"check_user: Database error while checking user: {e}")
        raise DatabaseError("Error checking user in the database.")

    except Exception as e:
        logger.error(f"check_user: Unexpected error while checking user: {e}")
        raise RuntimeError("Error checking user.")


async def check_db_connection(db: AsyncSession) -> bool:
    """
    Verifies if the database connection is active and operational.
    Used for health checks to ensure the database is responsive and working properly.
    """
    try:
        logger.info("check_db_connection: Checking the database connection.")

        # Execute a simple query to test the database connection
        result = db.execute(select(1))

        # Return True if the connection is valid (i.e., the query succeeds)
        return result.scalars().first() is not None

    except DatabaseError as e:
        logger.error(f"check_db_connection: Database connection error: {e}")
        raise DatabaseError("Error checking database connection.")

    except Exception as e:
        logger.error(f"check_db_connection: Error checking database connection: {e}")
        raise RuntimeError("Error checking database connection.")


async def save_active_token(db: AsyncSession, user_id: int, active_token: str):
    """
    Save or update the active token for a given user.
    This function is used to track the current active token associated with the user.
    """
    try:
        logger.info(
            f"save_active_token: Saving or updating active token for user {user_id}"
        )
        result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        db_token = result.scalar_one_or_none()

        if db_token:
            db_token.active_token = active_token
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the updated token
        else:
            db_token = ActiveToken(active_token=active_token, user_id=user_id)
            db.add(db_token)
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the new active token
    except IntegrityError as e:
        logger.error(
            f"save_active_token: Integrity error while saving active token: {e}"
        )
        db.rollback()
        raise IntegrityError("Error with unique constraints while saving active token.")
    except DatabaseError as e:
        logger.error(
            f"save_active_token: Database error while saving active token: {e}"
        )
        db.rollback()
        raise DatabaseError("Error saving active token to the database.")
    except Exception as e:
        logger.error(f"save_active_token: Error saving active token: {e}")
        db.rollback()
        raise RuntimeError("Error saving active token.")


async def check_active_token(
    db: AsyncSession, user_id: int = None, active_token: str = None
) -> ActiveToken | None:
    """
    Check if an active token exists for the user.
    This function is used to verify the user's current active token during authentication or token refresh.
    """
    try:
        if user_id:
            logger.info(f"check_active_token: Checking active token for user {user_id}")
            result = db.execute(
                select(ActiveToken).filter(ActiveToken.user_id == user_id)
            )
            return (
                result.scalar_one_or_none()
            )  # Return the active token if found, otherwise None
        if active_token:
            logger.info(f"check_active_token: Checking active token {active_token}")
            result = db.execute(
                select(ActiveToken).filter(ActiveToken.active_token == active_token)
            )
            return (
                result.scalar_one_or_none()
            )  # Return the active token if found, otherwise None
    except NoResultFound as e:
        logger.error(f"check_active_token: No active token found for the user: {e}")
        raise NoResultFound("Active token not found.")
    except Exception as e:
        logger.error(f"check_active_token: Error checking active token: {e}")
        raise RuntimeError("Error checking active token.")


async def delete_active_token(
    db: AsyncSession, user_id: int = None, active_token: str = None
) -> bool:
    if not user_id and not active_token:
        logger.error(
            "delete_active_token: Neither user_id nor active_token was provided."
        )
        raise RuntimeError("Either user_id or active_token must be provided.")

    try:
        logger.info(
            f"delete_active_token: Attempting to delete active token for user_id={user_id} or active_token={active_token}"
        )

        query = None
        if user_id:
            query = select(ActiveToken).filter(ActiveToken.user_id == user_id)
            logger.info(f"delete_active_token: Filtering by user_id={user_id}")
        elif active_token:
            query = select(ActiveToken).filter(ActiveToken.active_token == active_token)
            logger.info(
                f"delete_active_token: Filtering by active_token={active_token}"
            )

        result = db.execute(query)
        db_token = result.scalar_one_or_none()

        if db_token:
            logger.info(
                f"delete_active_token: Found active token, deleting token: {db_token}"
            )
            db.delete(db_token)
            db.commit()
            logger.info("delete_active_token: Successfully deleted active token.")
            return True

        logger.warning("delete_active_token: No active token found to delete.")
        return False

    except DatabaseError as e:
        logger.error(
            f"delete_active_token: Database error while deleting active token: {e}"
        )
        db.rollback()
        raise DatabaseError("Error deleting active token from the database.")
    except Exception as e:
        logger.error(
            f"delete_active_token: Unexpected error while deleting active token: {e}"
        )
        db.rollback()
        raise RuntimeError("Error deleting active token.")
