import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# NOTE: the document router lives in app/deprecated/ - see that folder's README.
from app.api.dependencies import close_neo4j_service, get_neo4j_service
from app.api.routes import graph, network, query
from app.config import settings
from app.utils.logging_utils import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


def _auto_process_sample_data() -> None:
    """Ingest any new CSV files sitting in backend/sample_data on startup."""
    from app.services.auto_processor import scan_and_process_csv_files

    sample_data_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "sample_data"
    )

    if not os.path.exists(sample_data_dir):
        logger.debug(f"Sample data directory not found: {sample_data_dir}")
        return

    logger.info(f"Scanning {sample_data_dir} for CSV files...")
    results = scan_and_process_csv_files(sample_data_dir, get_neo4j_service())

    if not results:
        logger.info("No new CSV files to process")
        return

    for result in results:
        if result.get("status") == "success":
            valid = result.get("processing_summary", {}).get("valid_connections", 0)
            logger.info(
                f"Auto-processed {result.get('filename')}: "
                f"Graph ID = {result.get('graph_id')}, Connections = {valid}"
            )
        else:
            logger.warning(
                f"Failed to process {result.get('filename')}: {result.get('error')}"
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown for the application."""
    logger.info("Starting Network Security Graph RAG API")

    if settings.enable_auto_process:
        try:
            _auto_process_sample_data()
        except Exception as e:
            # Auto-processing is a convenience, never a reason to fail startup.
            logger.error(f"Error in auto-processing: {e}")
    else:
        logger.info("Auto-processing disabled (ENABLE_AUTO_PROCESS=false)")

    yield

    logger.info("Shutting down Network Security Graph RAG API")
    close_neo4j_service()


# Create FastAPI application
app = FastAPI(
    title="Network Security Graph RAG API",
    description="API for network security analysis with knowledge graphs and RAG",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS middleware configuration.
# Credentials cannot be combined with a wildcard origin, so only allow them
# when the configured origins are explicit.
_allow_credentials = "*" not in settings.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(graph.router, prefix=settings.api_prefix, tags=["Graph Operations"])
app.include_router(query.router, prefix=settings.api_prefix, tags=["RAG Queries"])
app.include_router(network.router, prefix=settings.api_prefix, tags=["Network Security"])


@app.get("/health")
async def health_check():
    """Health check endpoint with database connectivity check."""
    logger.debug("Health check endpoint called")

    try:
        get_neo4j_service().list_graphs()
    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "error": "Database connection lost",
                "detail": "Unable to connect to Neo4j",
            },
        )

    return {
        "status": "healthy",
        "version": app.version,
        "database": "connected",
    }
