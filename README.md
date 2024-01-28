# FastAPI and SQLModel User Authentication: A Straightforward Approach to Implementing JWT

Welcome to my comprehensive guide on user authentication in FastAPI and SQLModel, where I demystify the process and present you with a straightforward approach to implementing JSON Web Tokens (JWT). In the ever-evolving landscape of web development, ensuring secure user authentication is paramount, and FastAPI combined with SQLModel provides an excellent foundation for building robust applications.

In this blog post, I'll take you on a journey through the intricacies of user authentication, breaking down the steps to implement JWT seamlessly into your FastAPI and SQLModel-based projects. My goal is to provide you with a clear and concise roadmap, allowing you to enhance the security of your applications without unnecessary complexity.

## Prerequisites

Before we delve into the implementation, let's make sure our development environment is set up with the necessary tools and dependencies. For the purpose of this tutorial, I'll be using Poetry as the dependency manager, but you can seamlessly switch to pip if that's your preference.

### Dependencies

We'll be working with the following essential libraries:

- **FastAPI**: A contemporary, high-performance web framework crafted for efficient API development in Python.

- **SQLModel**: An instinctive Object-Relational Mapper (ORM) specifically tailored for FastAPI applications, streamlining database interactions.

- **python-jose[cryptography]**: This pivotal library adeptly manages JSON Web Tokens (JWT) and relies on the cryptography package for robust encryption.

- **passlib[bcrypt]==3.2.2**: Employed for secure and efficient password hashing, ensuring the safeguarding of sensitive user credentials. The specified version (3.2.2) is chosen for compatibility, as FastAPI try to access the `__about` attribute [that was removed from the package in later versions](https://github.com/pyca/bcrypt/issues/684).

- **python-multipart**: Facilitates the seamless handling of multipart/form-data requests, enhancing the versatility of our application.

- **pydantic-settings**: A vital dependency empowering us with structured configuration settings through Pydantic, facilitating the seamless management and validation of configurations.

For the smooth execution of our application, `uvicorn` is employed. Additionally, to ensure secure local testing and execution, we rely on `python-dotenv` to read and manage configuration details from .env files. This approach guarantees a safe and controlled environment for local development and testing, while Pydantic-Settings adds an extra layer of configurability to our project.

### Installation

To install these dependencies, use the following commands based on your chosen package manager:

- **Poetry:**
  ```bash
  poetry add fastapi sqlmodel "python-jose[cryptography]" "passlib[bcrypt]" python-multipart uvicorn python-dotenv pydantic-setting
  ```

- **pip:**
  ```bash
  pip install fastapi sqlmodel "python-jose[cryptography]" "passlib[bcrypt]" python-multipart uvicorn python-dotenv pydantic-setting
  ```

Ensure you run these commands in your terminal to set up your development environment correctly.

Now that our dependencies are in place, open your preferred code editor, and we're all set to dive into the coding aspect of our tutorial!

## File Structure

While many tutorials demonstrate building features in a single file, real-world applications benefit from a well-organized and modular file structure. When working with FastAPI, I find it advantageous to follow a structured "master plan" for the file organization:

```
.
├── app
│  ├── __init__.py
│  ├── core
│  │  ├── __init__.py
│  │  ├── auth_util.py
│  │  ├── config.py
│  │  ├── logger.py
│  │  └── validators.py
│  ├── database.py
│  ├── main.py
│  ├── models
│  │  ├── __init__.py
│  │  ├── token.py
│  │  └── user.py
│  └── routers
│     ├── __init__.py
│     └── auth.py
├── app.db
├── poetry.lock
├── pyproject.toml
└── README.md
```

### Structure Overview:


- **`app`**: The main application directory.
  - **`core`**: Contains core functionalities.
    - **`auth_util.py`**: Handles utility functions related to authentication.
    - **`config.py`**: Manages configuration settings.
    - **`logger.py`**: Defines a custom logger for the application.
    - **`validators.py`**: Holds custom validators for input data.
  - **`database.py`**: Initializes the database connection and defines models.
  - **`main.py`**: The primary entry point for the FastAPI application.
  - **`models`**: Houses data models for the application.
    - **`token.py`**: Defines the token model for JSON Web Tokens (JWT).
    - **`user.py`**: Contains the User model for database interactions.
  - **`routers`**: Includes API route implementations.
    - **`auth.py`**: Implements authentication-related API routes.

- **`app.db`**: SQLite database file storing application data.

- **`poetry.lock`**: Records exact versions of dependencies for reproducibility using Poetry.

- **`pyproject.toml`**: Specifies project metadata and dependencies using the Poetry package manager.

- **`README.md`**: Documentation providing an overview of the project for developers and users.

This file structure fosters a modular and scalable development approach. Each module and directory has a specific purpose, making it easier to navigate and extend as your project grows. As we progress through the tutorial, we'll explore the contents of these directories and files in detail, gradually building our FastAPI user authentication module.

## The Core Package

In this package we'll keep all our internal logic, i.e, code to help our code. Here, we've got the essential internal workings that make our application stand tall. It's like the backstage crew – not in the spotlight, but absolutely crucial for the show to go on.

Picture this package as the "back-end of the back-end," where all the cool stuff happens. We're talking utilities, validators, and everything that makes our FastAPI application click. It's the engine room, quietly powering the whole operation.

So, let's take a stroll through the Core Module. We'll break down the details that keep our application running smoothly.


## The config.py

In any robust backend application, proper configuration is key. Meet the `Settings` class, a powerful tool leveraging Pydantic to manage and validate configuration settings for your FastAPI backend. Let's take a look:


```python
from typing import Optional

from dotenv import load_dotenv
from pydantic import AnyHttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo
from pydantic_settings import BaseSettings


load_dotenv()


class settings(BaseSettings):

    PROJECT_NAME: str
    BACKEND_CORS_ORIGINS: list[AnyHttpUrl] = []
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URI: Optional[str] = None

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLITE_DB_PATH: Optional[str] = None

    @field_validator("SQLITE_DB_PATH", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
        return v or ":memory:"

    class ConfigDict:

        case_sensitive = True
        env_file = ".env"


settings = settings()

```
### Explanation
Let's break down the code and its functionality step by step:

1. **Importing Necessary Modules**

    ```python
    from typing import Optional

    from dotenv import load_dotenv
    from pydantic import AnyHttpUrl, field_validator
    from pydantic_core.core_schema import ValidationInfo
    from pydantic_settings import BaseSettings
    ```

    - **`typing`:** Importing the `Optional` type for handling optional attribute types.
    - **`dotenv`:** Loading environment variables from a `.env` file using `load_dotenv`.
    - **`pydantic`:** Importing necessary components for Pydantic, a data validation library.
    - **`pydantic_core`:** Importing components for core Pydantic functionality.
    - **`pydantic_settings`:** Importing `BaseSettings` from Pydantic, a base class for configuration settings.

2. **Loading Environment Variables**

    ```python
    load_dotenv()
    ```

    - Invoking `load_dotenv()` to load environment variables from a `.env` file.

3. **Defining the `Settings` Class**

    ```python
    class settings(BaseSettings):
        # ... (attributes and methods go here)
    ```

    - A class that inherits from `BaseSettings`, the Pydantic base class for configuration settings.

4. **Configuring Attributes**

    ```python
    PROJECT_NAME: str
    BACKEND_CORS_ORIGINS: list[AnyHttpUrl] = []
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URI: Optional[str] = None
    ```

    - **`PROJECT_NAME`:** Attribute for storing the name of the project.
    - **`BACKEND_CORS_ORIGINS`:** Attribute representing a list of allowed CORS origins for the backend.
    - **`SECRET_KEY`:** Attribute for storing the secret key.
    - **`ALGORITHM`:** Attribute representing the algorithm for encoding JWT tokens, defaulting to "HS256".
    - **`ACCESS_TOKEN_EXPIRE_MINUTES`:** Attribute defining the expiry time for access tokens in minutes, defaulting to 30.
    - **`DATABASE_URI`:** Attribute for storing the URI of the database connection, with an optional default value of `None`.

5. **Defining Methods**:

    1. `assemble_cors_origins` Method:

    ```python
    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str] | str:
        # ... (method implementation goes here)
    ```

    - **Method Purpose:** Assembling CORS origins based on the provided value.
    - **Arguments:**
    - `v (str | List[str]):` The value to be assembled, which can be a string or a list of strings.
    - **Returns:**
    - `list[str] | str:` The assembled CORS origins.
    - **Raises:**
    - `ValueError:` If the value is not a string or a list of strings.

    2. `assemble_db_connection` Method:

    ```python
    SQLITE_DB_PATH: Optional[str] = None

    @field_validator("SQLITE_DB_PATH", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
        # ... (method implementation goes here)
    ```

    - **Method Purpose:** Assembling the SQLite database connection URI based on the provided value.
    - **Arguments:**
    - `v:` The value of the database path.
    - **Returns:**
    - `str:` The assembled SQLite database connection URI.

6. **Inner Class `ConfigDict`**

    ```python
    class ConfigDict:
        # ... (configuration options go here)
    ```

    - **Inner Class Purpose:** Defining configuration options for the settings.
    - **Attributes:**
    - `case_sensitive (bool):` A flag indicating whether the configuration is case-sensitive.
    - `env_file (str):` The name of the environment file to load settings from.
    - **Note:**
    - For enhanced security, it is recommended to store sensitive information in environment variables rather than directly in configuration files, especially when dealing with production databases.

7. **Instantiating the `Settings` Class**

    ```python
    settings = settings()
    ```

    - Instantiating an object of the `Settings` class, allowing access to configured values for the FastAPI application.

    This configuration module provides a structured and validated set of settings for a FastAPI backend. It covers essential attributes such as project name, CORS origins, secret key, algorithm, and database URI. The methods ensure the proper assembly of CORS origins and database connection URIs, and the inner class (`ConfigDict`) offers additional configuration options for the settings.

### Logging Configuration for FastAPI Application

Logging is a crucial aspect of any application, providing insights into its runtime behavior and helping developers diagnose issues. In the context of a FastAPI backend, the provided code demonstrates a configuration for logging using the built-in `logging` module in Python. Let's break down the code and understand each part:

### Importing the Logging Module:

```python
import logging
```

- **Purpose:** Importing the Python `logging` module for handling log-related functionalities.

### Creating a Logger Instance:

```python
logger = logging.getLogger(__name__)
```

- **Purpose:** Creating a logger instance with the name `__name__`, which typically represents the module name.
- **Note:** Naming the logger instance allows for better organization when dealing with multiple modules.

### Configuring Logger Level and Propagation:

```python
logger.setLevel(logging.DEBUG)
logger.propagate = False
```

- **Purpose:**
  - Setting the logging level to `DEBUG`, allowing all messages to be captured.
  - Disabling propagation to prevent log messages from being passed up the logger hierarchy.

### Formatting the Log Messages:

```python
formatter = logging.Formatter(
    r"%(asctime)s - %(levelname)-7s %(threadName)-12s [%(filename)s:%(lineno)s - %(funcName)s()] - %(message)s"
)
```

- **Purpose:** Defining a log message format for better readability.
- **Format Components:**
  - `%asctime`: Timestamp when the log message was created.
  - `%levelname`: Log level (e.g., INFO, WARNING).
  - `%threadName`: Name of the thread.
  - `%filename`: Name of the file where the log message originated.
  - `%lineno`: Line number in the file.
  - `%funcName`: Name of the function where the log message originated.
  - `%message`: The actual log message.

### Creating a StreamHandler and Adding it to the Logger:

```python
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
```

- **Purpose:**
  - Creating a `StreamHandler` to output log messages to the console.
  - Setting the formatter for the handler to the defined format.

### Logging Test Messages:

```python
if __name__ == "__main__":
    logger.info("Info logging test")
    logger.warning("Warning logging test")
    logger.error("Error logging test")
    logger.exception(Exception("Exception logging test"))
```

- **Purpose:**
  - Testing the configured logger by emitting log messages of various levels.
  - Using `logger.info`, `logger.warning`, and `logger.error` for standard log messages.
  - Using `logger.exception` to log an exception with traceback information.


The provided code sets up a flexible and informative logging configuration for a FastAPI application. It allows developers to customize the log format, specify the logging level, and direct log messages to different outputs. This robust logging setup proves invaluable during development, debugging, and maintenance phases, providing a clear trail of events within the application.


## Validators

In our project, the `validators.py` module is where we create special validators for pydantic and SQLModel classes. Currently, it's empty because we haven't needed any custom validators. However, as your project grows, this module is there to handle any specific validation requirements you might have in the future. It's a space reserved for making sure our data models meet unique validation criteria when needed.

## Auth Util

Here will be stored the methods we'll use to encrypt user password, and create JWTs. The code looks like this:

```python
from datetime import datetime, timedelta
import bcrypt

from jose import jwt

from app.core.config import settings
from datetime import timezone


def encrypt_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def generate_token(
    username: str, expires_delta=settings.ACCESS_TOKEN_EXPIRE_MINUTES
):
    data = {"sub": username}
    exprires = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    data |= {"exp": exprires}

    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

```

### Explanation

Let's delve into the code to understand each function:

1. **Encrypting Passwords**

    ```python
    def encrypt_password(password):
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    ```

    - **Purpose:** This function takes a plain-text password, hashes it using bcrypt, and returns the hashed password as a string.

2. **Checking Passwords**

    ```python
    def check_password(password, hashed):
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    ```

    - **Purpose:** Verifies a plain-text password against its hashed counterpart. Returns `True` if the match is successful, indicating a correct password.

3. **Generating JWTs**

    ```python
    def generate_token(username: str, expires_delta=settings.ACCESS_TOKEN_EXPIRE_MINUTES):
        data = {"sub": username}
        exprires = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
        data |= {"exp": exprires}

        return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    ```

    - **Purpose:** Creates a JWT for a given username with an optional expiration time. The resulting JWT is encoded using the secret key and algorithm specified in the application settings.

4. **Decoding JWTs**

    ```python
    def decode_token(token):
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    ```

    - **Purpose:** Decodes a provided JWT using the secret key and algorithm. This function ensures the integrity and authenticity of the token.


These functions play a vital role in our authentication system, providing secure handling of user credentials and the generation/verification of JWTs for authorized access.

## app package

After exploring the helper methods and classes within the `core` package, let's shift our focus to the contents of the `app` package. Here, we'll uncover the various files and functionalities that make up the core components of our FastAPI application.

## Database Creation and Configuration

In the `database.py` module, we establish and configure our database using SQLAlchemy. This module encapsulates key functionalities such as database engine configuration, session creation, and a base class for declarative models. Let's break down the code to understand its components:

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import sessionmaker, as_declarative

from app.core.config import settings

# Configure the database engine
engine = create_engine(settings.DATABASE_URI, pool_pre_ping=True)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@as_declarative()
class Base:
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()

```
### Explanation

1. **Configuring the Database Engine**

    ```python
    # Configure the database engine
    engine = create_engine(settings.DATABASE_URI, pool_pre_ping=True)
    ```

    - **Purpose:** This line configures the SQLAlchemy database engine using the `create_engine` function. The `settings.DATABASE_URI` should be pre-configured in the `app.core.config` module. The `pool_pre_ping=True` option helps to handle disconnections efficiently.

2. **Creating a Session Factory**

    ```python
    # Create a session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    ```

    - **Purpose:** The `SessionLocal` variable represents a session factory, enabling the creation of database sessions. It is configured with options for autocommit, autoflush, and the bound database engine.

3. Declarative Base Class:

    ```python
    @as_declarative()
    class Base:
        @declared_attr
        def __tablename__(cls) -> str:
            return cls.__name__.lower()
    ```

    - **Purpose:** This section defines a base class (`Base`) for declarative models using SQLAlchemy's declarative base. It includes a default implementation for the `__tablename__` attribute based on the lowercase name of the class. This simplifies the process of defining models by automatically setting the table name.


- **Important Note:** Before using this module, ensure that you configure the `settings.DATABASE_URI` in the `app.core.config` module. The example provides a guide on how to set up the database URI.

This `database.py` module sets the foundation for our database interactions in the FastAPI application, offering a convenient way to configure the database engine, create sessions, and define declarative models.

## The Main file

The `main.py` module not only sets up the FastAPI application but also establishes crucial elements such as CORS middleware and endpoints.

```python
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from app.core.config import settings
from app.routers import auth


def get_application():
    _app = FastAPI(title=settings.PROJECT_NAME)

    # Configure CORS middleware
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include the auth router
    _app.include_router(auth.router)

    return _app


app = get_application()


@app.get("/")
def test_connection():
    return {"status": "ok"}


def main():
    uvicorn.run(
        "app.main:app", host="0.0.0.0", port=os.getenv("PORT", 8000), reload=False
    )


if __name__ == "__main__":
    main()
```

### Explanation

1. **FastAPI Application Configuration:**

    ```python
    _app = FastAPI(title=settings.PROJECT_NAME)
    ```

    - **Purpose:** Creates a FastAPI application instance with the specified title from the application settings.

2. **CORS Middleware Configuration:**

    ```python
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    ```

    - **Purpose:** Configures Cross-Origin Resource Sharing (CORS) middleware to handle requests from specified origins. The settings.BACKEND_CORS_ORIGINS list defines allowed origins.

3. **Router Inclusion:**

    ```python
    _app.include_router(auth.router)
    ```

    - **Purpose:** Includes the router from the `auth` module in the application. This router handles authentication-related endpoints.

4. **Test Endpoint Definition:**

    ```python
    @app.get("/")
    def test_connection():
        return {"status": "ok"}
    ```

    - **Purpose:** Defines a test endpoint at the root path ("/") to check the status of the connection. Responds with a JSON indicating the status as "ok".

5. **Application Instance:**

    ```python
    app = get_application()
    ```

    - **Purpose:** Creates the main FastAPI application instance by calling the `get_application` function.

6. **Main Function for Running the Application:**

    ```python
    def main():
        uvicorn.run(
            "app.main:app", host="0.0.0.0", port=os.getenv("PORT", 8000), reload=False
        )
    ```

    - **Purpose:** Defines the main function responsible for running the FastAPI application using UVicorn. The host is set to "0.0.0.0", and the port can be customized using the PORT environment variable.

7. **Running the Application:**

    ```python
    if __name__ == "__main__":
        main()
    ```

    - **Purpose:** Executes the main function if the script is run directly, initiating the FastAPI application with UVicorn. The application will be accessible at http://localhost:8000 by default, and the port can be customized using the PORT environment variable.

This `main.py` file serves as the entry point for our FastAPI application, configuring the app, setting up middleware, defining routes, and running the application using UVicorn.

## Data Models with SQLModel

In this section, we introduce SQLModel, a powerful tool that streamlines the process of defining and managing data models in our FastAPI application. While FastAPI commonly employs a combination of Pydantic and SQLAlchemy ORM classes, SQLModel simplifies this by providing a unified package. With SQLModel, we can craft our Object-Relational Mapping (ORM) just once, combining the benefits of Pydantic for data validation and SQLAlchemy for database interactions. This integration enhances the efficiency and simplicity of working with data models in our FastAPI project.

## Token Models

In this section, we define the models responsible for handling tokens in our API. Tokens play a crucial role in securing communication between the client and our FastAPI application. Below is the model definition:

```python
from sqlmodel import SQLModel


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str = None

```

### Explanation:

1. **Token Model**
    ```python
    from sqlmodel import SQLModel

    class Token(SQLModel):
        access_token: str
        token_type: str
    ```
   - **Purpose:** This model (`Token`) is designed to represent the structure of tokens used for authentication in our API.
   - **Attributes:**
     - `access_token`: A string representing the access token generated during authentication.
     - `token_type`: A string specifying the type of token, commonly "bearer" for OAuth 2.0.

2. **Token Data Model**
    ```python
    class TokenData(SQLModel):
        username: str = None
    ```
   - **Purpose:** The `TokenData` model is responsible for capturing additional data associated with the token, particularly the username.
   - **Attributes:**
     - `username`: A string indicating the username associated with the token. Defaults to `None` to accommodate scenarios where a username might not be applicable.

These token models facilitate the secure exchange of information between clients and our FastAPI application, enhancing the overall security of our authentication mechanisms. The `Token` model represents the structure of tokens, while the `TokenData` model captures relevant data associated with these tokens.

## User Models

In this section, we define the models related to user data in our FastAPI application. These models cover aspects such as user creation, reading, and the base structure. Let's take a look into it:

```python
from typing import Optional
from sqlalchemy import Column, Integer, String
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    username: str


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    suceess: bool


class User(UserBase, table=True):
    id: Optional[int] = Field(
        default=None,
        sa_column=Column(
            Integer, primary_key=True, index=True, unique=True, autoincrement=True
        ),
    )
    username: str = Field(sa_column=Column(Integer, unique=True, index=True))
    password: str = Field(sa_column=Column(String))

```

### Explanation:

1. **User Base Model:**
    ```python
    class UserBase(SQLModel):
        username: str
    ```
   - **Purpose:** The `UserBase` model serves as the foundational structure for user-related data, defining the basic attributes.
   - **Attributes:**
     - `username`: A string representing the username of the user.

2. **User Create Model:**
    ```python
    class UserCreate(UserBase):
        password: str
    ```
   - **Purpose:** The `UserCreate` model extends the `UserBase` model, including an additional attribute for password when creating a new user.
   - **Attributes:**
     - `username`: A string representing the username of the user.
     - `password`: A string representing the password of the user.

3. **User Read Model:**
    ```python
    class UserRead(UserBase):
        suceess: bool
    ```
   - **Purpose:** The `UserRead` model extends the `UserBase` model, adding a boolean attribute indicating the success of a read operation.
   - **Attributes:**
     - `username`: A string representing the username of the user.
     - `suceess`: A boolean indicating the success of the read operation.

4. **User Model (Database Representation):**
    ```python
    class User(UserBase, table=True):
        id: Optional[int] = Field(
            default=None,
            sa_column=Column(
                Integer, primary_key=True, index=True, unique=True, autoincrement=True
            ),
        )
        username: str = Field(sa_column=Column(Integer, unique=True, index=True))
        password: str = Field(sa_column=Column(String))
    ```
   - **Purpose:** The `User` model represents the user data structure in the database, incorporating fields for database operations.
   - **Attributes:**
     - `id`: An optional integer serving as the primary key, automatically incremented for new entries.
     - `username`: A string representing the username of the user (unique in the database).
     - `password`: A string representing the password of the user.

These user models provide a comprehensive framework for managing user data within our FastAPI application, covering creation, reading, and database representation aspects.

## Authentication Router

Now with all our preparations completed, lets finally implement our authentication (remember when this was the point of this article?).
Lets take a look at our final module:

```python
from datetime import datetime, timedelta
from typing import Annotated

from fastapi.responses import JSONResponse
from app.core.auth_util import (
    check_password,
    decode_token,
    encrypt_password,
    generate_token,
)

from app.database import SessionLocal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from app.models import user as user_model
from app.models import token as token_model
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlmodel import SQLModel
from starlette import status

from app.core.config import settings
from app.core.logger import logger

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

bcrypt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


@router.post(
    "/signup", status_code=status.HTTP_201_CREATED, response_model=user_model.UserRead
)
async def create_user(
    user_create: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> user_model.User:
    try:
        with SessionLocal() as db:
            existing_user = (
                db.query(user_model.User)
                .filter(user_model.User.username == user_create.username)
                .first()
            )
            if not existing_user:
                user_create.password = encrypt_password(user_create.password)
                db_user = user_model.User.model_validate(user_create)
                db.add(db_user)
                db.commit()
                db.refresh(db_user)
                return user_model.UserRead(username=db_user.username, suceess=True)
    except Exception as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from e
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="User already exists",
    )


@router.post("/token", response_model=token_model.Token)
async def login_for_access_token(
    token: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> token_model.Token:
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token.username)
            .first()
        )
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_NOT_FOUND,
                detail="Incorrect username",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not check_password(token.password, db_user.password):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token = generate_token(username=token.username)
        return token_model.Token(access_token=access_token, token_type="bearer")


@router.get("/me")
async def read_users_me(
    token: Annotated[str, Depends(oauth2_bearer)],
) -> user_model.UserRead:
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = token_model.TokenData(username=username)
    except JWTError as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token_data.username)
            .first()
        )
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user_model.UserRead(username=db_user.username, suceess=True)

```


### Explanation:

1. **Router Configuration:**
    router = APIRouter(
        prefix="/auth",
        tags=["auth"],
    )
    ```
   - **Explanation:**
     - Configure the authentication router using `APIRouter`. It will define all our routers to have the same prefix and tags as stablished

2. **Router Constants and Objects:**
    ```python
    SECRET_KEY = settings.SECRET_KEY
    ALGORITHM = settings.ALGORITHM
    
    bcrypt = CryptContext(schemes=["bcrypt"], deprecated="auto")
    oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")
    ```
   - **Explanation:**
     - Retrieve secret key and algorithm from application settings.
     - Configure a `CryptContext` object for password hashing using the bcrypt scheme.
     - Create an OAuth2PasswordBearer object for token authentication, specifying the token URL.

3. **User Creation Endpoint:**
    ```python
    @router.post(
        "/signup", status_code=status.HTTP_201_CREATED, response_model=user_model.UserRead
    )
    async def create_user(
        user_create: Annotated[OAuth2PasswordRequestForm, Depends()],
    ) -> user_model.User:
    ```
   - **Explanation:**
     - Define a POST endpoint `/auth/signup` for user creation.
     - Utilize the `OAuth2PasswordRequestForm` to receive form data for username and password.
     - Return a `UserRead` response model.

4. **User Creation Implementation:**
    ```python
    try:
        with SessionLocal() as db:
            existing_user = (
                db.query(user_model.User)
                .filter(user_model.User.username == user_create.username)
                .first()
            )
            if not existing_user:
                user_create.password = encrypt_password(user_create.password)
                db_user = user_model.User.model_validate(user_create)
                db.add(db_user)
                db.commit()
                db.refresh(db_user)
                return user_model.UserRead(username=db_user.username, suceess=True)
    except Exception as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from e
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="User already exists",
    )
    ```
   - **Explanation:**
     - Attempt to create a new user in the database.
     - Check if the user already exists based on the provided username.
     - Encrypt the user's password and add the user to the database.
     - Handle exceptions, log errors, and raise appropriate HTTP exceptions.

5. **Token Generation Endpoint:**
    ```python
    @router.post("/token", response_model=token_model.Token)
    async def login_for_access_token(
        token: Annotated[OAuth2PasswordRequestForm, Depends()],
    ) -> token_model.Token:
    ```
   - **Explanation:**
     - Define a POST endpoint `/auth/token` for token generation.
     - Utilize the `OAuth2PasswordRequestForm` to receive form data for username and password.
     - Return a `Token` response model.

6. **Token Generation Implementation:**
    ```python
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token.username)
            .first()
        )
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_NOT_FOUND,
                detail="Incorrect username",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not check_password(token.password, db_user.password):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token = generate_token(username=token.username)
        return token_model.Token(access_token=access_token, token_type="bearer")
    ```
   - **Explanation:**
     - Verify the provided username and password against the database.
     - Raise appropriate HTTP exceptions for incorrect credentials.
     - Generate an access token using the `generate_token` function.
     - Return the generated token.

7. **User Retrieval Endpoint:**
    ```python
    @router.get("/me")
    async def read_users_me(
        token: Annotated[str, Depends(oauth2_bearer)],
    ) -> user_model.UserRead:
    ```
   - **Explanation:**
     - Define a GET endpoint `/auth/me` for retrieving user information.
     - Utilize the OAuth2 bearer token for authentication.
     - Return a `UserRead` response model.

8. **User Retrieval Implementation:**
    ```python
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = token_model.TokenData(username=username)
    except JWTError as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token_data.username)
            .first()
        )
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",        
            )
        return user_model.UserRead(username=db_user.username, suceess=True)
    ```
   - **Explanation:**
     - Attempt to decode and verify the provided JWT token.
     - Extract the username from the token payload.
     - Raise HTTP exceptions for invalid credentials or token decoding errors.
     - Retrieve the user from the database based on the username.
     - Return the user information using the `UserRead` response model.

This authentication router manages user creation, token generation, and user information retrieval, providing essential functionality for securing our FastAPI application.

## Testing our app
Run our app, and enter in the `docs` (http://0.0.0.0:8000/docs).
This is what you should see:

![Docs Main Page](https://i.imgur.com/xgifq5l.png)

### Creating a User
Lets create a user with the `/auth/signup` endpoint:

![SignUp](https://i.imgur.com/e1Xd4Bj.png)

We should have a `201` response, containing our username, and a confirmation of success:

![201 response](https://i.imgur.com/iDX1b0J.png)

If we try to re-create the same user, we should, have an error, and that is indeed what happens:

![409 response](https://i.imgur.com/JT0UDNM.png)

### Getting the token

Lets create the access token with the `/auth/token` endpoint

![Token Get](https://i.imgur.com/S3UEyuv.png)

Which indeed creates the token!

![200 response](https://i.imgur.com/4Fx9fys.png)

### Retrieving information
Finally, we can get the `/auth/me` using the token for authentication!

![get me](https://i.imgur.com/ZD1LPjo.png)

## Conclusion

In conclusion, this guide has equipped you with the knowledge and tools to effortlessly integrate user authentication using JSON Web Tokens into your FastAPI and SQLModel projects. By unraveling the intricacies of this process, we have navigated through the steps, ensuring a seamless implementation that enhances the security of your applications. FastAPI, coupled with SQLModel, proves to be an ideal combination for building robust and secure web applications. As you embark on your journey in the ever-evolving landscape of web development, the straightforward approach presented here empowers you to prioritize and achieve a paramount aspect of application development—secure user authentication. May your projects thrive with the newfound knowledge and the resilient foundation of FastAPI and SQLModel. Happy coding!