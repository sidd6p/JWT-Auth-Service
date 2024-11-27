import logging
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import UserCreate, UserLogin, Token, RevokeTokenRequest
from app.database import get_db
from sqlalchemy.exc import IntegrityError, DatabaseError

from app.utils import (
    check_db_connection,
    verify_password,
    create_access_token,
    decode_token,
    delete_active_token,
    check_active_token,
    save_active_token,
    save_new_user,
    check_user,
    log_route,
)

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")],
)

logger = logging.getLogger(__name__)

router = APIRouter()


# Signup - Create new user and issue a new token
@router.post("/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def sign_up(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Handles user signup by creating a new user in the database if the email is not already registered.
    If successful, generates and returns an access token for the new user.
    """
    log_route(
        "/signup", logging.INFO, f"Signup request received for email: {user.email}"
    )

    # Check if the user with the given email already exists
    db_user = await check_user(db, user.email)
    if db_user:
        log_route(
            "/signup",
            logging.WARNING,
            f"Signup failed: Email already registered for {user.email}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered. Please use a different email.",
        )

    try:
        # Create a new user in the database
        user_id = await save_new_user(db, user)
        log_route(
            "/signup",
            logging.INFO,
            f"User created successfully with email: {user.email}",
        )

        # Generate an access token for the new user
        access_token = await create_access_token(data={"user_id": user_id})

        # Save the access token as active for the user
        await save_active_token(db, user_id, access_token)

        return {"access_token": access_token, "token_type": "bearer"}

    except IntegrityError as e:
        log_route(
            "/signup",
            logging.ERROR,
            f"Integrity error during signup for email {user.email}: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered. Please use a different email.",
        )
    except DatabaseError as e:
        log_route(
            "/signup",
            logging.ERROR,
            f"Database error during signup for email {user.email}: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while processing signup. Please try again later.",
        )
    except Exception as e:
        log_route(
            "/signup",
            logging.ERROR,
            f"Unexpected error during signup for email {user.email}: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while processing signup. Please try again later.",
        )


# Signin - Authenticate user and replace old token with new one
@router.post("/signin", response_model=Token, status_code=status.HTTP_200_OK)
async def sign_in(user: UserLogin, db: AsyncSession = Depends(get_db)):
    log_route(
        "/signin", logging.INFO, f"Signin request received for email: {user.email}"
    )

    # Check if the user exists
    db_user = await check_user(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        log_route(
            "/signin",
            logging.WARNING,
            f"Signin failed: Invalid credentials for email: {user.email}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please check your email and password.",
        )

    try:
        # Check and delete existing active token
        token_deleted = await delete_active_token(db, user_id=db_user.id)
        if token_deleted:
            log_route(
                "/signin", logging.INFO, f"Old token revoked for user ID: {db_user.id}"
            )
    except Exception as e:
        log_route(
            "/signin",
            logging.ERROR,
            f"Error while revoking old token for user ID {db_user.id}: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke the existing token. Please try again later.",
        )

    # Create a new token
    try:
        access_token = await create_access_token(data={"user_id": db_user.id})
        await save_active_token(db, db_user.id, access_token)

        log_route(
            "/signin",
            logging.INFO,
            f"User signed in successfully for email: {user.email}",
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        log_route(
            "/signin",
            logging.ERROR,
            f"Error during token generation or save for user ID {db_user.id}: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate a new token. Please try again later.",
        )


# Refresh - Remove the old token and create a new one
@router.post("/refresh", response_model=Token, status_code=status.HTTP_200_OK)
async def refresh_token(
    request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)
):
    active_token = request.access_token
    log_route(
        "/refresh",
        logging.INFO,
        f"Refresh token request received for token: {active_token}",
    )

    try:
        if await check_active_token(db, active_token=active_token):
            log_route("/refresh", logging.INFO, f"Old token is valid: {active_token}")
        else:
            log_route(
                "/refresh",
                logging.WARNING,
                f"The provided token is invalid or already revoked: {active_token}",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is invalid or already revoked.",
            )

        decoded = await decode_token(active_token)

        if await delete_active_token(db, active_token=active_token):
            log_route(
                "/refresh",
                logging.INFO,
                f"Old token revoked successfully: {active_token}",
            )
        else:
            log_route(
                "/refresh", logging.WARNING, f"Token already revoked: {active_token}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is invalid or already revoked.",
            )

        new_token = await create_access_token(data={"user_id": decoded["user_id"]})
        await save_active_token(db, decoded["user_id"], new_token)

        log_route(
            "/refresh",
            logging.INFO,
            f"Token refreshed successfully for user ID: {decoded['user_id']}",
        )
        return {"access_token": new_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        log_route(
            "/refresh",
            logging.WARNING,
            f"Refresh failed: Expired token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired.",
        )
    except jwt.InvalidTokenError:
        log_route(
            "/refresh",
            logging.WARNING,
            f"Refresh failed: Invalid token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except Exception as e:
        log_route(
            "/refresh", logging.ERROR, f"Unexpected error during token refresh: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later.",
        )


# Revoke - Delete the token (either by user or by token)
@router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke_token(request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)):
    active_token = request.access_token
    log_route(
        "/revoke",
        logging.INFO,
        f"Revoke token request received for token: {active_token}",
    )

    try:
        if await check_active_token(db, active_token=active_token):
            log_route("/revoke", logging.INFO, f"Old token is valid: {active_token}")
        else:
            log_route(
                "/revoke",
                logging.WARNING,
                f"The provided token is invalid or already revoked: {active_token}",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is invalid or already revoked.",
            )

        if await delete_active_token(db, active_token=active_token):
            log_route(
                "/revoke", logging.INFO, f"Token revoked successfully: {active_token}"
            )
            return {"message": "Token revoked successfully."}
        else:
            log_route(
                "/revoke",
                logging.WARNING,
                f"Token already revoked or invalid: {active_token}",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is invalid or already revoked.",
            )
    except jwt.ExpiredSignatureError:
        log_route(
            "/revoke",
            logging.WARNING,
            f"Revoke failed: Expired token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired.",
        )
    except jwt.InvalidTokenError:
        log_route(
            "/revoke",
            logging.WARNING,
            f"Revoke failed: Invalid token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except Exception as e:
        log_route(
            "/revoke", logging.ERROR, f"Unexpected error during token revocation: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke token due to a server error. Please try again later.",
        )


# Authorize Token - Check if the provided token is valid and authorized
@router.post("/authorize-token", response_model=Token, status_code=status.HTTP_200_OK)
async def authorize_token(
    request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)
):
    """
    Verifies the validity of the provided access token. If the token is valid and authorized,
    returns the token and associated user data. If not, raises an error.
    """
    active_token = request.access_token
    log_route(
        "/authorize-token",
        logging.INFO,
        f"Authorization request received for token: {active_token}",
    )

    try:
        # Check if the token is active and authorized in the database
        decoded = await check_active_token(db, active_token=active_token)
        if decoded:
            log_route(
                "/authorize-token", logging.INFO, f"Token is authorized: {active_token}"
            )

            # Return the token and associated user data if valid
            return {
                "access_token": active_token,
                "token_type": "bearer",
                "user_id": decoded["user_id"],
            }
        else:
            log_route(
                "/authorize-token",
                logging.WARNING,
                f"Unauthorized or revoked token: {active_token}",
            )
            raise jwt.InvalidTokenError("Invalid JWT token.")
    except jwt.ExpiredSignatureError:
        log_route(
            "/authorize-token",
            logging.WARNING,
            f"Authorization failed: Expired token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token has expired.",
        )
    except jwt.InvalidTokenError:
        log_route(
            "/authorize-token",
            logging.WARNING,
            f"Authorization failed: Invalid token used: {active_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except Exception as e:
        log_route(
            "/authorize-token",
            logging.ERROR,
            f"Unexpected error during token authorization: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to authorize token due to a server error. Please try again later.",
        )


# Health check - Ensure database connection is active
@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Checks if the database connection is active and operational.
    Returns a healthy status if the database connection is successful.
    """
    log_route("/health", logging.INFO, "Health check endpoint hit.")

    try:
        # Verify the database connection by executing a simple query
        result_value = await check_db_connection(db)

        if result_value == 1:
            log_route("/health", logging.INFO, "Database connection is healthy.")
            return {"status": "healthy"}
        else:
            log_route(
                "/health",
                logging.ERROR,
                f"Unexpected result from database during health check (result_value={result_value}).",
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected result from database. Health check failed.",
            )

    except Exception as e:
        log_route("/health", logging.ERROR, f"Database connection error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error. Please try again later.",
        )
