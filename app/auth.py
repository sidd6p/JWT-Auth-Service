import logging
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import (
    UserCreate,
    UserLogin,
    Token,
    RevokeTokenRequest,
    AuthorizeResponse,
)
from app.database import get_db

from app.utils import (
    check_db_connection,
    verify_password,
    create_access_token,
    delete_access_token,
    check_access_token,
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


@router.post("/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def sign_up(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Handles the user signup process by:
    1. Checking if the email is already registered in the database.
    2. Creating a new user in the database if the email is not already taken.
    3. Generating an access token for the newly created user.
    4. Returning the generated token and its type as "bearer".

    If any step fails (e.g., email already registered, database issues), an appropriate error is logged,
    and an HTTPException is raised with a corresponding error message.
    """
    log_route(
        "/signup", logging.INFO, f"Signup request received for email: {user.email}"
    )

    # Check if the user with the given email already exists in the database
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
        # Create a new user in the database, hash the password, and return the user ID
        user_id = await save_new_user(db, user)
        log_route(
            "/signup",
            logging.INFO,
            f"User created successfully with email: {user.email}",
        )

        # Generate and save an access token for the new user using the user ID
        access_token = await create_access_token(db, data={"user_id": user_id})

        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        log_route(
            "/signup",
            logging.ERROR,
            f"An error occurred during signup for email {user.email}: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request. Please try again later.",
        )


@router.post("/signin", response_model=Token, status_code=status.HTTP_200_OK)
async def sign_in(user: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticates a user by:
    1. Verifying the user's email and password.
    2. If valid, generating a new access token for the user.
    3. Invalidating any previous tokens associated with the user.
    4. Returning the new access token with the token type "bearer".

    If authentication fails (invalid credentials), an HTTPException is raised with an appropriate error message.
    """
    log_route(
        "/signin", logging.INFO, f"Signin request received for email: {user.email}"
    )

    # Check if the user exists and verify their password
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
        # Generate a new access token for the user
        access_token = await create_access_token(db, data={"user_id": db_user.id})

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


@router.put("/refresh", response_model=Token, status_code=status.HTTP_200_OK)
async def refresh_token(
    request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)
):
    """
    Refreshes the user's access token by:
    1. Validating the provided old token.
    2. If valid, generating a new access token for the user.
    3. Invalidating the old token.
    4. Returning the new access token with the token type "bearer".

    If any step fails (e.g., token expired, invalid token), an appropriate error is logged,
    and an HTTPException is raised with a corresponding error message.
    """
    access_token = request.access_token

    log_route(
        "/refresh",
        logging.INFO,
        f"Refresh token request received for token: {access_token}",
    )

    try:
        # Validate the old token
        payload = await check_access_token(db=db, access_token=access_token)
        log_route("/refresh", logging.INFO, f"Old token is valid: {access_token}")

        # Generate a new access token for the user
        new_token = await create_access_token(
            db=db, data={"user_id": payload["user_id"]}
        )

        log_route(
            "/refresh",
            logging.INFO,
            f"Token refreshed successfully for user ID: {payload['user_id']}",
        )

        return {"access_token": new_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError as e:
        log_route(
            "/refresh",
            logging.ERROR,
            f"Refresh failed: Expired token used: {access_token} : {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired.",
        )

    except jwt.InvalidTokenError as e:
        log_route(
            "/refresh",
            logging.WARNING,
            f"Refresh failed: Invalid token used: {access_token} : {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    except Exception as e:
        log_route(
            "/refresh", logging.ERROR, f"Unexpected error during token refresh: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later.",
        )


@router.delete("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)):
    """
    Revokes a user's access token by:
    1. Deleting the provided token from the database.
    2. Invalidating the token to prevent further use for authentication.
    3. If the token is not found, raises an error indicating the token is invalid.

    If an error occurs (e.g., invalid token or server error), an appropriate error message
    is logged, and an HTTPException is raised with a corresponding status and message.
    """
    access_token = request.access_token

    log_route(
        "/revoke",
        logging.INFO,
        f"Revoke token request received for token: {access_token}",
    )

    try:
        # Attempt to delete the token from the database
        await delete_access_token(db, access_token=access_token)
        log_route(
            "/revoke", logging.INFO, f"Token revoked successfully: {access_token}"
        )

    except jwt.InvalidTokenError as e:
        log_route(
            "/revoke",
            logging.ERROR,
            f"Revocation failed: Invalid token used: {access_token}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    except Exception as e:
        log_route(
            "/revoke", logging.ERROR, f"Unexpected error during token revocation: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke token due to a server error. Please try again later.",
        )


@router.get(
    "/authorize-token", response_model=AuthorizeResponse, status_code=status.HTTP_200_OK
)
async def authorize_token(
    request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)
):
    """
    Verifies the validity of the provided access token by:
    1. Checking if the token is active and authorized in the database.
    2. Returning the token and associated user data if valid.
    3. If invalid, raises an error with appropriate status and message.
    """
    access_token = request.access_token
    log_route(
        "/authorize-token",
        logging.INFO,
        f"Authorization request received for token: {access_token}",
    )

    try:
        # Check if the token is active and authorized in the database
        decoded = await check_access_token(db, access_token=access_token)
        log_route(
            "/authorize-token", logging.INFO, f"Token is authorized: {access_token}"
        )

        # Return the token and associated user data if valid
        return {
            "user_id": decoded["user_id"],
        }

    except jwt.ExpiredSignatureError as e:
        log_route(
            "/authorize-token",
            logging.WARNING,
            f"Authorization failed: Expired token used: {access_token} : {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token has expired.",
        )
    except jwt.InvalidTokenError as e:
        log_route(
            "/authorize-token",
            logging.WARNING,
            f"Authorization failed: Invalid token used: {access_token} : {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token",
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


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Checks the health of the database connection by:
    1. Verifying if the database connection is active.
    2. Returning a healthy status if the database is operational.
    3. Raising an error if the connection fails or the database is unavailable.
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
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Health Check failed. Database is unavailable.",
            )

    except Exception as e:
        log_route("/health", logging.ERROR, f"Database connection error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health Check failed. Database is unavailable.",
        )
