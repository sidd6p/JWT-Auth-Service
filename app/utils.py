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
    Hashes the user's password using bcrypt by:
    1. Using the bcrypt context to securely hash the provided password.
    2. Returning the hashed password if successful.
    3. Raising specific errors if there are issues during the hashing process.
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
    Verifies the plain password against the hashed password by:
    1. Using bcrypt to check if the provided plain password matches the stored hashed password.
    2. Returning `True` if the passwords match, otherwise `False`.
    3. Raising specific errors if there are issues during the verification process.
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


async def save_access_token(db: AsyncSession, user_id: int, access_token: str):
    """
    Saves or updates the active token for a given user by:
    1. Checking if an existing token for the user is present in the database.
    2. If an existing token is found, it updates the token with the new one.
    3. If no token is found, it creates a new active token for the user.
    4. Returning the saved or updated token.
    5. Raising specific errors if there are issues during the save or update process.
    """
    try:
        logger.info(
            f"save_access_token: Saving or updating active token for user {user_id}"
        )
        result = db.execute(select(ActiveToken).filter(ActiveToken.user_id == user_id))
        db_token = result.scalar_one_or_none()

        if db_token:
            db_token.access_token = access_token
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the updated token
        else:
            db_token = ActiveToken(access_token=access_token, user_id=user_id)
            db.add(db_token)
            db.commit()
            db.refresh(db_token)
            return db_token  # Return the new active token

    except DatabaseError as e:
        logger.error(
            f"save_access_token: Database error while saving active token: {e}"
        )
        db.rollback()
        raise DatabaseError("Error saving active token to the database.")
    except Exception as e:
        logger.error(f"save_access_token: Error saving active token: {e}")
        db.rollback()
        raise RuntimeError("Error saving active token.")


async def create_access_token(
    db: AsyncSession, data: dict, expires_delta: timedelta = None
) -> str:
    """
    Creates a JWT access token for a user by:
    1. Encoding the user data into a JWT token with an expiration time.
    2. Saving the access token associated with the user in the database.
    3. Returning the generated access token.
    4. Raising specific errors if there are issues during token creation or database operations.
    """

    try:
        logger.info("create_access_token: Creating JWT access token")
        to_encode = data.copy()
        expire = datetime.utcnow() + (
            expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": expire})  # Set expiration time for the token
        access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        await save_access_token(
            db=db, user_id=data["user_id"], access_token=access_token
        )
        return access_token

    except DatabaseError as e:
        logger.error(
            f"create_access_token: Database error while saving active token: {e}"
        )
        db.rollback()
        raise DatabaseError("Error saving active token to the database.")
    except ValueError as e:
        logger.error(
            f"create_access_token: Value error while creating access token: {e}"
        )
        raise ValueError("Error with input data while creating access token.")
    except Exception as e:
        logger.error(f"create_access_token: Error creating access token: {e}")
        raise RuntimeError("Error creating access token.")


async def decode_token(access_token: str):
    """
    Decodes the JWT token and returns the payload by:
    1. Verifying the token's signature using the secret key and algorithm.
    2. Returning the decoded payload if the token is valid.
    3. Raising specific errors if the token is expired, invalid, or if another error occurs.
    """
    try:
        logger.info("decode_token: Decoding the JWT token")
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
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
    Hashes the user's password and saves the user in the database by:
    1. Hashing the user's password securely.
    2. Creating a new user object and adding it to the database.
    3. Committing the changes to persist the new user.
    4. Returning the user's ID once the user is successfully saved.
    5. Raising specific errors if there are issues during database operations.
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
    Checks if a user with the given email exists in the database by:
    1. Querying the database for the user with the provided email.
    2. Returning the user object if found, or None if no matching user is found.
    3. Raising specific errors in case of database issues or other errors.
    """
    try:
        logger.info(f"check_user: Checking if user with email {email} exists.")

        # Query the database for a user with the given email
        result = db.execute(select(User).filter(User.email == email))

        # Return the user object if found, otherwise None
        return result.scalar_one_or_none()

    except DatabaseError as e:
        logger.error(f"check_user: Database error while checking user: {e}")
        raise DatabaseError("Error checking user in the database.")

    except Exception as e:
        logger.error(f"check_user: Unexpected error while checking user: {e}")
        raise RuntimeError("Error checking user.")


async def check_db_connection(db: AsyncSession) -> bool:
    """
    Verifies if the database connection is active and operational by:
    1. Executing a simple query to check the connection.
    2. Returning True if the connection is valid, or False if it fails.
    3. Raising specific errors if there is an issue with the database connection.
    """
    try:
        logger.info("check_db_connection: Checking the database connection.")

        # Execute a simple query to test the database connection
        result = db.execute(select(1))

        # Return True if the connection is valid (i.e., the query succeeds)
        return result.scalars().first() is not None

    except Exception as e:
        logger.error(f"check_db_connection: Error checking database connection: {e}")
        raise RuntimeError("Error checking database connection.")


async def check_access_token(
    db: AsyncSession, user_id: int = None, access_token: str = None
) -> ActiveToken | None:
    """
    Verifies if an active token exists for the given user or validates the provided token by:
    1. Checking if a user-specific active token exists and if it is expired.
    2. If the token is expired, it is deleted, and None is returned.
    3. Validating the provided access token and returning its payload if valid.
    4. Raising errors for expired or invalid tokens.
    5. Returning None if neither `user_id` nor `access_token` is provided.
    """
    try:
        if user_id:
            logger.info(f"check_access_token: Checking active token for user {user_id}")
            result = db.execute(
                select(ActiveToken).filter(ActiveToken.user_id == user_id)
            )
            db_token = result.scalar_one_or_none()

            # If token found, check if it's expired
            if db_token:
                payload = await decode_token(db_token.access_token)
                if "user_id" not in payload or "exp" not in payload:
                    raise jwt.InvalidTokenError("Invalid JWT token.")
                return payload  # Return the active token if valid
            raise jwt.InvalidTokenError("Invalid JWT token.")

        if access_token:
            logger.info(f"check_access_token: Checking active token {access_token}")
            result = db.execute(
                select(ActiveToken).filter(ActiveToken.access_token == access_token)
            )
            db_token = result.scalar_one_or_none()

            # If token found, check if it's expired
            if db_token:
                payload = await decode_token(db_token.access_token)
                if "user_id" not in payload or "exp" not in payload:
                    raise jwt.InvalidTokenError("Invalid JWT token.")
                return payload  # Return the active token if valid
            raise jwt.InvalidTokenError("Invalid JWT token.")

        # Return None if neither user_id nor access_token is provided
        logger.error("check_access_token: Neither user_id nor access_token provided.")
        return None

    except jwt.ExpiredSignatureError:
        await delete_access_token(db, access_token=access_token)
        logger.warning("check_access_token: Token is Expired")
        raise jwt.ExpiredSignatureError("Token is Expired")
    except jwt.InvalidTokenError:
        logger.warning("check_access_token: Invalid token.")
        raise jwt.InvalidTokenError("Invalid token.")
    except Exception as e:
        logger.error(f"check_access_token: Error decoding token: {e}")
        raise RuntimeError("Error decoding token.")


async def delete_access_token(
    db: AsyncSession, user_id: int = None, access_token: str = None
) -> bool:
    """
    Deletes an active token from the database by:
    1. Searching for a token using either `user_id` or `access_token`.
    2. Deleting the found token if it exists.
    3. Raising an error if no token is found or if the deletion process fails.
    4. Handling specific errors such as invalid token or database issues.
    """
    try:
        logger.info(
            f"delete_access_token: Attempting to delete active token for user_id={user_id} or access_token={access_token}"
        )

        query = None
        if user_id:
            query = select(ActiveToken).filter(ActiveToken.user_id == user_id)
            logger.info(f"delete_access_token: Filtering by user_id={user_id}")
        elif access_token:
            query = select(ActiveToken).filter(ActiveToken.access_token == access_token)
            logger.info(
                f"delete_access_token: Filtering by access_token={access_token}"
            )

        result = db.execute(query)
        db_token = result.scalar_one_or_none()

        if db_token:
            logger.info(
                f"delete_access_token: Found active token, deleting token: {db_token}"
            )
            db.delete(db_token)
            db.commit()
            logger.info("delete_access_token: Successfully deleted active token.")
            return

        logger.warning("delete_access_token: No active token found to delete.")
        raise jwt.InvalidTokenError("Invalid JWT token.")

    except jwt.InvalidTokenError:
        logger.warning("delete_access_token: Invalid token.")
        raise jwt.InvalidTokenError("Invalid token.")
    except DatabaseError as e:
        logger.error(
            f"delete_access_token: Database error while deleting active token: {e}"
        )
        db.rollback()
        raise DatabaseError("Error deleting active token from the database.")
    except Exception as e:
        logger.error(
            f"delete_access_token: Unexpected error while deleting active token: {e}"
        )
        db.rollback()
        raise RuntimeError("Error deleting active token.")
