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
    check_db_connection
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
            detail="Email already registered. Please use a different email."
        )
    
    try:
        await save_new_user(db, user)

        logger.info("User created successfully for email: %s", user.email)
        access_token = await create_access_token(data={"user": user.email})
        
        await save_active_token(db, user.email, access_token)
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error("Error during signup for email %s: %s", user.email, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error. Please try again later."
        )

# Signin - Authenticate user and replace old token with new one
@router.post("/signin", response_model=Token, status_code=status.HTTP_200_OK)
async def sign_in(user: UserLogin, db: AsyncSession = Depends(get_db)):
    logger.info("Signin request received for email: %s", user.email)
    db_user = await check_user(db, user.email)
    
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        logger.warning("Signin failed: Invalid credentials for email: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please check your email and password."
        )
    
    access_token = await check_active_token(db, user.email)
    
    if access_token:
        await delete_active_token(db, user=user.email)
    
    access_token = await create_access_token(data={"user": db_user.email})
    
    await save_active_token(db, user.email, access_token)

    logger.info("User signed in successfully for email: %s", user.email)
    return {"access_token": access_token, "token_type": "bearer"}

# Revoke - Delete the token (either by user or by token)
@router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke_token(request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)):
    token = request.access_token
    logger.info("Revoke token request received for token: %s", token)

    if await delete_active_token(db, token=token):
        logger.info("Token revoked successfully: %s", token)
        return {"message": "Token revoked successfully."}
    else:
        logger.warning("Token already revoked or invalid: %s", token)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided token is Invalid or already revoked."
        )

# Refresh - Remove the old token and create a new one
@router.post("/refresh", response_model=Token, status_code=status.HTTP_200_OK)
async def refresh_token(request: RevokeTokenRequest, db: AsyncSession = Depends(get_db)):
    token = request.access_token
    logger.info("Refresh token request received for token: %s", token)
    
    try:
        decoded = await decode_token(token)
        if "user" not in decoded or "exp" not in decoded:
            logger.warning("Refresh failed: Invalid token used: %s", token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The provided token is Invalid."
            )

        if await delete_active_token(db, token=token):
            logger.info("Old token revoked successfully: %s", token)
        else:
            logger.warning("Token already revoked: %s", token)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The provided token is Invalid or already revoked."
            )
        
        new_token = await create_access_token(data={"user": decoded["user"]})
        
        await save_active_token(db, decoded["user"], new_token)
        
        logger.info("Token refreshed successfully for user: %s", decoded["user"])
        return {"access_token": new_token, "token_type": "bearer"}
    except jwt.ExpiredSignatureError:
        logger.warning("Refresh failed: Expired token used: %s", token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The provided token is expired."
        )
    except jwt.InvalidTokenError:
        logger.warning("Refresh failed: Invalid token used: %s", token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        logger.error("Unexpected error during token refresh: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later."
        )

# Health check - Ensure database connection is active
@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_db)):
    logger.info("Health check endpoint hit")
    try:
        result_value = await check_db_connection(db) 
        print(result_value)

        if result_value == 1:
            logger.info("Database connection is healthy")
            return {"status": "healthy"}
        else:
            logger.error("Health check failed: Unexpected result from database")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected result from database. Health check failed."
            )
    except Exception as e:
        logger.error("Health check failed: Database connection error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error. Please try again later."
        )
