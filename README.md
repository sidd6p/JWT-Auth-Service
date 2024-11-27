
# API Documentation for Authentication and Token Management


## Table of Contents

1. [Overview](#overview)
2. [Endpoints](#endpoints)
   - [POST /signup](#post-signup)
   - [POST /signin](#post-signin)
   - [PUT /refresh](#put-refresh)
   - [DELETE /revoke](#delete-revoke)
   - [GET /authorize-token](#get-authorize-token)
   - [GET /health](#get-health)
3. [Database Configuration & Secret](#database-configuration--secret)
4. [Installation](#installation)
5. [Logging](#logging)
6. [Example Usage](#example-usage)
7. [Dependencies](#dependencies)
8. [License](#license)



## Overview
This API provides endpoints for user authentication, token generation, and management. It supports user signup, sign-in, token refresh, revocation, and health checks. The API is built using FastAPI and SQLAlchemy with async support for database operations.


## Endpoints

### `POST /signup`
- **Description**: Handles user signup. It checks if the email is already registered, creates a new user, and returns an access token.
- **Request Body**: 
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "your-access-token",
    "token_type": "bearer"
  }
  ```

### `POST /signin`
- **Description**: Authenticates a user by verifying their credentials and returning an access token.
- **Request Body**: 
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "your-access-token",
    "token_type": "bearer"
  }
  ```

### `PUT /refresh`
- **Description**: Refreshes an existing access token by validating the old token and generating a new one.
- **Request Body**:
  ```json
  {
    "access_token": "old-access-token"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "new-access-token",
    "token_type": "bearer"
  }
  ```

### `DELETE /revoke`
- **Description**: Revokes an access token by deleting it from the database.
- **Request Body**:
  ```json
  {
    "access_token": "access-token-to-revoke"
  }
  ```
- **Response**: 
  - Status: `204 No Content`

### `GET /authorize-token`
- **Description**: Verifies if an access token is valid and returns user data if the token is authorized.
- **Request Body**:
  ```json
  {
    "access_token": "valid-access-token"
  }
  ```
- **Response**:
  ```json
  {
    "user_id": 123
  }
  ```

### `GET /health`
- **Description**: Checks the health of the database connection.
- **Response**:
  ```json
  {
    "status": "healthy"
  }
  ```

## Database Configuration & Secret 

The service connects to a PostgreSQL database using the following environment variables:

- **POSTGRES_USER**: The PostgreSQL user.
- **POSTGRES_PASSWORD**: The PostgreSQL user's password.
- **POSTGRES_HOST**: The host of the PostgreSQL database (default: `localhost`).
- **POSTGRES_DB**: The name of the PostgreSQL database.

The application uses SQLAlchemy for database interaction, and `SessionLocal` provides access to the database session.

If the database does not exist, it will be created automatically using the `create_database_if_not_exists()` function.

For JWT and secret, it require following environment variables as well:
- **SECRET_KEY**: Random and big string
- **ACCESS_TOKEN_EXPIRE_MINUTES**: Expire time of JWT tokens

> You can check more details on env_example.txt file. 

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sidd6p/JWT-Auth-Service.git
   cd JWT-Auth-Service
   ```
2. Set up environment variables (e.g., database connection strings, secret keys) in a `.env` file.
   - Create .env file in folder
   - Copy paste the content of env_example.txt file into .env filr

4. Run the docker compose file:
   ```bash
   docker-compose up
   ```

   This will start the server on **port 8000** by default. Checkout here after running [Swagger UI](http://localhost:8000/docs)


## Logging
The API logs all requests and errors using Python's built-in logging module. The logs are saved to a file `app.log` and are also printed to the console.


## Example Usage
1. **Signup**:
   ```bash
    curl --location --request POST "http://localhost:8000/auth/signup" --header "Content-Type: application/json" --data-raw "{\"email\": \"abc@gmail.com\", \"password\": \"abc\"}"
   ```

2. **Sign-in**:
   ```bash
    curl --location --request POST "http://localhost:8000/auth/signin" --header "Content-Type: application/json" --data-raw "{\"email\": \"<your_email>\", \"password\": \"<your_password>\"}"
   ```

3. **Refresh Token**:
   ```bash
    curl --location --request PUT "http://localhost:8000/auth/refresh" --header "Content-Type: application/json" --data "{ \"access_token\": \"<access_token>\"}"
   ```

4. **Revoke Token**:
   ```bash
    curl --location --request DELETE "http://localhost:8000/auth/revoke" --header "Content-Type: application/json" --data "{ \"access_token\": \"<access_token>\"}"
   ```
   
5. **Authorize Token**:
   ```bash
    curl --location --request GET "http://localhost:8000/auth/authorize-token" --header "Content-Type: application/json" --data "{ \"access_token\": \"<access_token>\"}"
   ```

6. **Health Check**:
   ```bash
    curl -X GET "http://localhost:8000/auth/health"
   ```

## Dependencies
- FastAPI
- SQLAlchemy (Async)
- JWT (jsonwebtoken)
- PostgreSQL

## License
This project is licensed under the Apache License.

