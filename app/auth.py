import logging
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import UserCreate, UserLogin, Token, RevokeTokenRequest
from app.database import get_db

from app.utils import (
    verify_password,
    create_access_token,
    decode_token,
    delete_active_token,
    check_active_token,
    save_active_token,
    save_new_user,
    check_user,
    check_db_connection,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# Signup - Create new user and issue a new token
@router.post("/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def sign_up(user: UserCreate, db: AsyncSession = Depends(get_db)):
    logger.info("Signup request received for email: %s", user.email)
    db_user = await check_user(db, user.email)

    if db_user:
        logger.warning("Signup failed: Email already registered: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered. Please use a different email.",
        )

    try:
        user_id = await save_new_user(db, user)

        logger.info("User created successfully for email: %s", user.email)
        access_token = await create_access_token(data={"user_id": user_id})

        await save_active_token(db, user_id, access_token)
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error("Error during signup for email %s: %s", user.email, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error. Please try again later.",
        )


# Signin - Authenticate user and replace old token with new one
@router.post("/signin", response_model=Token, status_code=status.HTTP_200_OK)
async def sign_in(user: UserLogin, db: AsyncSession = Depends(get_db)):
    logger.info("Signin request received for email: %s", user.email)

    # Check if the user exists
    db_user = await check_user(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        logger.warning("Signin failed: Invalid credentials for email: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please check your email and password.",
        )

    try:
        # Check and delete existing active token
        token_deleted = await delete_active_token(db, user_id=db_user.id)
        if token_deleted:
            logger.info("Old token revoked for user ID: %s", db_user.id)
    except Exception as e:
        logger.error(f"Error while revoking old token for user ID {db_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke the existing token. Please try again later.",
        )

    # Create a new token
    try:
        access_token = await create_access_token(data={"user_id": db_user.id})
        await save_active_token(db, db_user.id, access_token)

        logger.info("User signed in successfully for email: %s", user.email)
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(
            f"Error during token generation or save for user ID {db_user.id}: {e}"
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
    logger.info("Refresh token request received for token: %s", active_token)

    try:
        if await check_active_token(db, active_token=active_token):
            logger.info("Old token is Valid: %s", active_token)
        else:
            logger.warning(
                "The provided token is Invalid or already revoked: %s", active_token
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is Invalid or already revoked.",
            )

        decoded = await decode_token(active_token)

        if await delete_active_token(db, active_token=active_token):
            logger.info("Old token revoked successfully: %s", active_token)
        else:
            logger.warning("Token already revoked: %s", active_token)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is Invalid or already revoked.",
            )

        new_token = await create_access_token(data={"user_id": decoded["user_id"]})
        await save_active_token(db, decoded["user_id"], new_token)

        logger.info("Token refreshed successfully for user: %s", decoded["user_id"])
        return {"access_token": new_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        logger.warning("Refresh failed: Expired token used: %s", active_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired.",
        )
    except jwt.InvalidTokenError:
        logger.warning("Refresh failed: Invalid token used: %s", active_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except Exception as e:
        logger.error("Unexpected error during token refresh: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later.",
        )


# Revoke - Delete the token (either by user or by token)
@router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke_token(request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)):
    active_token = request.access_token
    logger.info("Revoke token request received for token: %s", active_token)

    try:

        if await check_active_token(db, active_token=active_token):
            logger.info("Old token is Valid: %s", active_token)
        else:
            logger.warning(
                "The provided token is Invalid or already revoked: %s", active_token
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is Invalid or already revoked.",
            )

        if await delete_active_token(db, active_token=active_token):
            logger.info("Token revoked successfully: %s", active_token)
            return {"message": "Token revoked successfully."}
        else:
            logger.warning("Token already revoked or invalid: %s", active_token)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is Invalid or already revoked.",
            )
    except jwt.ExpiredSignatureError:
        logger.warning("Refresh failed: Expired token used: %s", active_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired.",
        )
    except jwt.InvalidTokenError:
        logger.warning("Refresh failed: Invalid token used: %s", active_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except Exception as e:
        logger.error("Unexpected error during token refresh: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later.",
        )


# Health check - Ensure database connection is active
@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_db)):
    logger.info("Health check endpoint hit")
    try:
        result_value = await check_db_connection(db)

        if result_value == 1:
            logger.info("Database connection is healthy")
            return {"status": "healthy"}
        else:
            logger.error("Health check failed: Unexpected result from database")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected result from database. Health check failed.",
            )
    except Exception as e:
        logger.error("Health check failed: Database connection error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error. Please try again later.",
        )
