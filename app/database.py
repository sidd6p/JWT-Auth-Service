import os
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@{os.getenv("POSTGRES_HOST", "localhost")}:5432/{os.getenv("POSTGRES_DB")}'

engine = create_engine(DATABASE_URL, connect_args={"options": "-csearch_path=public"})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def create_database_if_not_exists():
    """
    Check if the database exists, and create it if it doesn't.
    Uses a temporary engine connected to the default 'postgres' database.
    """
    temp_engine = create_engine(
        f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@{os.getenv("POSTGRES_HOST", "localhost")}:5432/postgres'
    )

    with temp_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        result = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
            {"dbname": os.getenv("POSTGRES_DB")},
        )
        if result.fetchone():
            print(f"Database '{os.getenv('POSTGRES_DB')}' already exists.")
        else:
            conn.execute(text(f"CREATE DATABASE {os.getenv('POSTGRES_DB')}"))
            print(f"Database '{os.getenv('POSTGRES_DB')}' created.")


create_database_if_not_exists()


def get_db():
    """
    Dependency for retrieving the database session.
    Ensures proper cleanup of the session after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


Base.metadata.create_all(bind=engine)
