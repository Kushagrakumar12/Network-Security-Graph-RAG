"""
Shared FastAPI dependencies.

This module is the single owner of the Neo4jService instance. Creating a
Neo4jService opens a driver connection pool, so the app must not construct one
per module — every consumer goes through get_neo4j_service().
"""

from typing import Optional

from app.config import settings
from app.services.neo4j_service import Neo4jService

_neo4j_service: Optional[Neo4jService] = None


def get_neo4j_service() -> Neo4jService:
    """Get the shared Neo4j service, creating it on first use."""
    global _neo4j_service
    if _neo4j_service is None:
        _neo4j_service = Neo4jService(
            uri=settings.neo4j_uri,
            user=settings.neo4j_user,
            password=settings.neo4j_password,
        )
    return _neo4j_service


def close_neo4j_service() -> None:
    """Close the shared Neo4j service. Called on application shutdown."""
    global _neo4j_service
    if _neo4j_service is not None:
        _neo4j_service.close()
        _neo4j_service = None
