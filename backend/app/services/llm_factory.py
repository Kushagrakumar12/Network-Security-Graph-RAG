import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


class GroqLLM:
    """Groq API client using httpx for fast async HTTP requests."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        # Read through settings rather than os.environ: pydantic-settings loads
        # .env into the Settings object without exporting it to the process
        # environment, so os.environ would miss anything configured in .env.
        self.api_key = api_key if api_key is not None else settings.groq_api_key
        self.model = model or settings.groq_model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

        if not self.api_key:
            raise ValueError("GROQ_API_KEY is required to use the Groq provider")
    
    def __call__(self, prompt: str, **kwargs) -> str:
        return self.invoke(prompt, **kwargs)
    
    def invoke(self, prompt: str, **kwargs) -> str:
        """Synchronous invocation using httpx."""
        try:
            import httpx
        except ImportError:
            # Fallback to requests if httpx not available
            return self._invoke_with_requests(prompt, **kwargs)
        
        logger.info(f"[LLM] Using Groq {self.model}")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        try:
            with httpx.Client(timeout=90.0) as client:
                response = client.post(self.base_url, headers=headers, json=data)
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            logger.error(f"[LLM] Groq API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"[LLM] Groq API error: {str(e)}")
            raise
    
    def _invoke_with_requests(self, prompt: str, **kwargs) -> str:
        """Fallback using requests library."""
        import requests
        
        logger.info(f"[LLM] Using Groq {self.model} (requests fallback)")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=90)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            logger.error(f"[LLM] Groq API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"[LLM] Groq API error: {str(e)}")
            raise
    
    async def ainvoke(self, prompt: str, **kwargs) -> str:
        """Async invocation for better performance."""
        import httpx
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(self.base_url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]


class OllamaLLM:
    """Ollama local LLM client (fallback for offline use)."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or settings.ollama_base_url
        self.model = model or settings.ollama_model
    
    def __call__(self, prompt: str, **kwargs) -> str:
        return self.invoke(prompt, **kwargs)
    
    def invoke(self, prompt: str, **kwargs) -> str:
        """Invoke Ollama API."""
        import requests
        
        logger.info(f"[LLM] Using Ollama {self.model} at {self.base_url}")
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", 0.2),
                "num_predict": kwargs.get("max_tokens", 4096)
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=data,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            logger.error(f"[LLM] Ollama error: {str(e)}")
            raise


def get_llm():
    """
    Factory function to get the configured LLM instance.

    Provider is chosen by LLM_PROVIDER: "groq" (default, fast online inference)
    or "ollama" (local inference).

    Returns:
        LLM instance with invoke() and __call__() methods

    Raises:
        ValueError: if the provider is unknown or its configuration is missing
    """
    provider = settings.llm_provider.lower().strip()

    logger.info(f"[LLM] Provider requested: {provider}")

    if provider == "groq":
        if not settings.groq_api_key:
            raise ValueError(
                "GROQ_API_KEY is not set. To use the Groq provider:\n"
                "  1. Get a free API key from https://console.groq.com\n"
                "  2. Set GROQ_API_KEY in your environment or backend/.env\n"
                "Alternatively set LLM_PROVIDER=ollama to run locally."
            )
        llm = GroqLLM()
        logger.info(f"[LLM] Initialized Groq with model: {llm.model}")
        return llm

    if provider == "ollama":
        llm = OllamaLLM()
        logger.info(f"[LLM] Initialized Ollama with model: {llm.model}")
        return llm

    raise ValueError(
        f"Unknown LLM provider: {provider!r}. Supported providers: groq, ollama"
    )