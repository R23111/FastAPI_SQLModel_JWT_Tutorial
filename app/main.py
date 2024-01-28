"""
Main module for running the FastAPI application.

This module sets up a FastAPI application, configures middleware for CORS, includes routers,
defines a test endpoint, and runs the application using UVicorn.

Usage:
    To run the application, execute this module. The application will be accessible at
    http://localhost:8000 by default, and the port can be customized using the PORT environment variable.

Example:
    $ python main.py

Note: Make sure to configure settings.PROJECT_NAME and settings.BACKEND_CORS_ORIGINS
in app.core.config before running this module.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from app.core.config import settings
from app.routers import auth


def get_application():
    """
    Create and configure the FastAPI application.

    Returns:
        FastAPI: The configured FastAPI application instance.
    """
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
    """
    Test endpoint to check the status of the connection.

    Returns:
        dict: A JSON response indicating the status as "ok".
    """
    return {"status": "ok"}


def main():
    """
    Main function to run the FastAPI application using UVicorn.

    This function uses UVicorn to run the FastAPI application on the specified host and port.

    Example:
        $ python main.py

    Note: The default host is "0.0.0.0" and the default port is 8000.
        The port can be customized using the PORT environment variable.
    """
    uvicorn.run(
        "app.main:app", host="0.0.0.0", port=os.getenv("PORT", 8000), reload=False
    )


if __name__ == "__main__":
    main()
