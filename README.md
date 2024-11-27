
# FastAPI Authentication Service

This repository contains a FastAPI-based authentication service with functionality for user signup, login, token refresh, token revocation, and health check. The service uses JWT for token management and integrates with an asynchronous database using SQLAlchemy.

## Features

- **Signup**: Create a new user and issue a new JWT token.
- **Signin**: Authenticate an existing user and issue a new JWT token.
- **Refresh**: Refresh an expired or revoked token with a new one.
- **Revoke**: Revoke (delete) an active token.
- **Health Check**: Ensure that the database connection is active and functional.

## API Endpoints

### `POST /signup`
Creates a new user and issues a JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "strongpassword"
}
```

**Response:**
```json
{
  "access_token": "jwt-token-here",
  "token_type": "bearer"
}
```

### `POST /signin`
Authenticates an existing user and returns a new JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "strongpassword"
}
```

**Response:**
```json
{
  "access_token": "jwt-token-here",
  "token_type": "bearer"
}
```

### `POST /refresh`
Refreshes an expired or revoked JWT token.

**Request Body:**
```json
{
  "access_token": "old-jwt-token"
}
```

**Response:**
```json
{
  "access_token": "new-jwt-token",
  "token_type": "bearer"
}
```

### `POST /revoke`
Revokes an active JWT token.

**Request Body:**
```json
{
  "access_token": "jwt-token-here"
}
```

**Response:**
```json
{
  "message": "Token revoked successfully."
}
```

### `GET /health`
Checks the health of the database connection.

**Response:**
```json
{
  "status": "healthy"
}
```

## Database Configuration

The service connects to a PostgreSQL database using the following environment variables:

- **POSTGRES_USER**: The PostgreSQL user.
- **POSTGRES_PASSWORD**: The PostgreSQL user's password.
- **POSTGRES_HOST**: The host of the PostgreSQL database (default: `localhost`).
- **POSTGRES_DB**: The name of the PostgreSQL database.

The application uses SQLAlchemy for database interaction, and `SessionLocal` provides access to the database session.

If the database does not exist, it will be created automatically using the `create_database_if_not_exists()` function.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sidd6p/JWT-Auth-Service.git
   cd JWT-Auth-Service
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables (e.g., database connection strings, secret keys) in a `.env` file.

5. Run the FastAPI application:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

   This will start the server on **port 8000** by default.

## Dependencies

- FastAPI
- SQLAlchemy
- JWT
- Uvicorn
- Python 3.x

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
