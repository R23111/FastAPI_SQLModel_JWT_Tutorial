from typing import Optional

from dotenv import load_dotenv
from pydantic import AnyHttpUrl, field_validator
from pydantic_core.core_schema import ValidationInfo
from pydantic_settings import BaseSettings


load_dotenv()


class settings(BaseSettings):
    """
    Configuration settings for the app backend.

    Attributes:
        PROJECT_NAME: The name of the project.
        BACKEND_CORS_ORIGINS: A list of allowed CORS origins for the backend.

    Methods:
        assemble_cors_origins(cls, v: str | list[str]) -> list[str] | str:
            Assembles the CORS origins based on the provided value.
        assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
            Assembles the SQLite database connection URI based on the provided value.

    Inner class:
        ConfigDict:
            Configuration options for the settings.

    """

    PROJECT_NAME: str
    BACKEND_CORS_ORIGINS: list[AnyHttpUrl] = []
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URI: Optional[str] = None

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str] | str:
        """
        Assembles the CORS origins based on the provided value.

        Args:
            v (str | List[str]): The value to be assembled. It can be a string or a list of strings.

        Returns:
            list[str] | str: The assembled CORS origins.

        Raises:
            ValueError: If the value is not a string or a list of strings.

        """
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLITE_DB_PATH: Optional[str] = None

    @field_validator("SQLITE_DB_PATH", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> str:
        """
        Assembles the SQLite database connection URI based on the provided value.

        Args:
            v: The value of the database path.

        Returns:
            str: The assembled SQLite database connection URI.

        """
        return v or ":memory:"

    class ConfigDict:
        """
        Configuration options for the settings. When using production databases like MySQL and PostgreSQL,
        it is recommended to store secrets in environment variables. This class facilitates reading those variables.

        Attributes:
            case_sensitive (bool): A flag indicating whether the configuration is case-sensitive.
            env_file (str): The name of the environment file to load settings from.

        Note:
            For enhanced security, consider storing sensitive information in environment variables rather than
            directly in configuration files, especially when dealing with production databases.
        """

        case_sensitive = True
        env_file = ".env"


settings = settings()
