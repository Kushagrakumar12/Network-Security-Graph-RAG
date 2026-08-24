import json
from pathlib import Path
from typing import Annotated, List, Union

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Anchor .env to the backend/ directory (the parent of app/) rather than the
# process working directory, so config loads the same way whether uvicorn is
# started from backend/, from the repo root, or from /app inside Docker.
BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    """
    Application settings, read from environment variables and .env.

    Field names map to upper-case environment variables automatically
    (cors_origins -> CORS_ORIGINS), so no explicit env= binding is needed.
    """

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API settings
    api_prefix: str = "/api"
    debug: bool = False
    log_level: str = "INFO"
    api_timeout: int = 120

    # Comma-separated in .env, e.g. CORS_ORIGINS=http://localhost:3000,http://localhost:8080
    #
    # NoDecode is required: without it pydantic-settings runs json.loads() on the
    # raw environment value inside EnvSettingsSource, which happens BEFORE any
    # field validator, so a comma-separated value raises SettingsError and the
    # app dies at startup. NoDecode hands the raw string to _split_cors_origins.
    cors_origins: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )

    # Set ENABLE_AUTO_PROCESS=false to skip ingesting sample_data/*.csv on startup
    enable_auto_process: bool = True

    # Neo4j settings
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # LLM settings - Groq is the default (fast online inference)
    llm_provider: str = "groq"  # "groq" or "ollama"

    # Groq API (primary)
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    # Ollama (fallback - local inference, requires pulling the model first)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"

    # Ingestion limits
    max_file_size_mb: int = 10
    max_csv_rows: int = 5000

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Union[str, List[str], None]) -> List[str]:
        """
        Accept a comma-separated string, a JSON array, or a real list.

        NoDecode on the field disables pydantic-settings' own JSON decoding, so
        both documented spellings are handled here:
            CORS_ORIGINS=http://localhost:3000,http://localhost:8080
            CORS_ORIGINS=["http://localhost:3000"]
        """
        if value is None:
            return ["http://localhost:3000"]

        if isinstance(value, str):
            text = value.strip()
            if not text:
                return ["http://localhost:3000"]

            # JSON array form, e.g. '["http://a", "http://b"]'
            if text.startswith("["):
                try:
                    decoded = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"CORS_ORIGINS looks like a JSON array but is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(decoded, list):
                    raise ValueError("CORS_ORIGINS JSON must be an array of strings")
                return [str(origin).strip() for origin in decoded if str(origin).strip()]

            return [origin.strip() for origin in text.split(",") if origin.strip()]

        return value

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper


# Create settings instance
settings = Settings()

# Kept in sync with the FastAPI app metadata in app/main.py
VERSION = "2.0.0"
PROJECT_NAME = "Network Security Graph RAG"
