import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import text
from app.schemas import UserCreate, UserLogin, Token
from app.models import User, TokenBlacklist
from app.database import get_db
from app.utils import hash_password, verify_password, create_access_token, decode_token


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()  
    ],
)

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
def sign_up(user: UserCreate, db: Session = Depends(get_db)):
    logger.info("Signup request received for email: %s", user.email)
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        logger.warning("Signup failed: Email already registered: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered. Please use a different email."
        )
    try:
        new_user = User(email=user.email, hashed_password=hash_password(user.password))
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("User created successfully for email: %s", user.email)
        access_token = create_access_token(data={"sub": new_user.email})
        return {"access_token": access_token, "token_type": "bearer"}
    except SQLAlchemyError as e:
        logger.error("Database error during signup for email %s: %s", user.email, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user due to a server error. Please try again later."
        )

@router.post("/signin", response_model=Token, status_code=status.HTTP_200_OK)
def sign_in(user: UserLogin, db: Session = Depends(get_db)):
    logger.info("Signin request received for email: %s", user.email)
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        logger.warning("Signin failed: User not found for email: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found. Please sign up first."
        )
    if not verify_password(user.password, db_user.hashed_password):
        logger.warning("Signin failed: Invalid credentials for email: %s", user.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please check your email and password."
        )
    access_token = create_access_token(data={"sub": db_user.email})
    logger.info("User signed in successfully for email: %s", user.email)
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/revoke", status_code=status.HTTP_200_OK)
def revoke_token(token: str, db: Session = Depends(get_db)):
    logger.info("Revoke token request received for token: %s", token)
    try:
        revoked_token = TokenBlacklist(token=token)
        db.add(revoked_token)
        db.commit()
        logger.info("Token revoked successfully: %s", token)
        return {"message": "Token revoked successfully."}
    except SQLAlchemyError as e:
        logger.error("Database error during token revocation: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke token due to a server error. Please try again later."
        )

@router.get("/refresh", response_model=Token, status_code=status.HTTP_200_OK)
def refresh_token(old_token: str, db: Session = Depends(get_db)):
    logger.info("Refresh token request received for token: %s", old_token)
    try:
        decoded = decode_token(old_token)
        db_revoked = db.query(TokenBlacklist).filter(TokenBlacklist.token == old_token).first()
        if db_revoked:
            logger.warning("Refresh failed: Revoked token used: %s", old_token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The provided token has been revoked."
            )
        new_token = create_access_token(data={"sub": decoded["sub"]})
        logger.info("Token refreshed successfully for user: %s", decoded["sub"])
        return {"access_token": new_token, "token_type": "bearer"}
    except SQLAlchemyError as e:
        logger.error("Database error during token refresh: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh token due to a server error. Please try again later."
        )

@router.get("/health", status_code=status.HTTP_200_OK)
def health_check(db: Session = Depends(get_db)):
    logger.info("Health check endpoint hit")
    try:
        db.execute(text("SELECT 1")).first()
        logger.info("Database connection is healthy")
        return {"status": "healthy", "message": "Database connection is working fine."}
    except SQLAlchemyError as e:
        logger.error("Health check failed: Database connection error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection failed. Please check the server logs for more details."
        )
