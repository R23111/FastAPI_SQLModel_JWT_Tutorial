"""
This module provides database-related functionality using SQLAlchemy.

It includes the configuration for the database engine, session creation, and a base class for declarative models.

Note: Make sure to configure the settings.DATABASE_URI in app.core.config before using this module.

Example:
    settings.DATABASE_URI = "postgresql://user:password@localhost/db_name"

    from mymodule import Base, SessionLocal

    # Now you can use the Base class to define your models, and SessionLocal to interact with the database.
"""

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
    """
    Base class for declarative models using SQLAlchemy.

    This class includes a default implementation for __tablename__ based on the class name in lowercase.

    Example:
        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True, index=True)
            username = Column(String, index=True)

        In this example, the __tablename__ for the User model will be automatically set to "users".
    """

    @declared_attr
    def __tablename__(cls) -> str:
        """
        Define the default __tablename__ for the declarative model.

        Returns:
            str: The lowercase name of the class as the table name.
        """
        return cls.__name__.lower()
