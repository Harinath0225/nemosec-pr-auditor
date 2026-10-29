"""
Environment configuration loader and Nebius Token Factory LLM factory.
Supports runtime overrides from the UI settings drawer and persists to .env.
"""
import os
from pathlib import Path
from dotenv import load_dotenv, set_key
from langchain_openai import ChatOpenAI

ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT_DIR / ".env"
HOME_ENV_PATH = Path.home() / ".env"

# Load from home ~/.env first (if any), then project .env
if HOME_ENV_PATH.exists():
    load_dotenv(HOME_ENV_PATH, override=False)
if ENV_PATH.exists():
    load_dotenv(ENV_PATH, override=True)


class Settings:
    """Dynamic runtime settings backed by environment variables."""

    @property
    def nebius_api_key(self) -> str:
        key = os.getenv("NEBIUS_API_KEY", "").strip()
        if key in ("", "your_nebius_api_key_here"):
            return ""
        return key

    @property
    def nebius_base_url(self) -> str:
        return os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1").strip()

    @property
    def nebius_model(self) -> str:
        return os.getenv("NEBIUS_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B").strip()

    @property
    def github_token(self) -> str:
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token in ("", "your_github_personal_access_token_here"):
            return ""
        return token

    @property
    def default_github_repo(self) -> str:
        return os.getenv("DEFAULT_GITHUB_REPO", "Harinath0225/nemosec-pr-auditor").strip()

    def update(self, nebius_api_key: str | None = None, nebius_model: str | None = None, github_token: str | None = None):
        """Update runtime settings and persist to project .env."""
        if not ENV_PATH.exists():
            ENV_PATH.write_text("", encoding="utf-8")
        if nebius_api_key is not None and nebius_api_key.strip():
            os.environ["NEBIUS_API_KEY"] = nebius_api_key.strip()
            set_key(str(ENV_PATH), "NEBIUS_API_KEY", nebius_api_key.strip())
        if nebius_model is not None and nebius_model.strip():
            os.environ["NEBIUS_MODEL"] = nebius_model.strip()
            set_key(str(ENV_PATH), "NEBIUS_MODEL", nebius_model.strip())
        if github_token is not None and github_token.strip():
            os.environ["GITHUB_TOKEN"] = github_token.strip()
            set_key(str(ENV_PATH), "GITHUB_TOKEN", github_token.strip())


settings = Settings()

AVAILABLE_MODELS = [
    {
        "id": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        "label": "NVIDIA Nemotron-3 Nano 30B-A3B (Fast / Default)",
        "tier": "Fast MoE",
    },
    {
        "id": "nvidia/nemotron-3-super-120b",
        "label": "NVIDIA Nemotron-3 Super 120B (Deep Reasoning)",
        "tier": "Reasoning",
    },
    {
        "id": "nvidia/nemotron-3.5-super-vl",
        "label": "NVIDIA Nemotron-3.5 Super VL (Multimodal)",
        "tier": "Vision-Language",
    },
]


def get_nebius_llm(temperature: float = 0.2, model_override: str | None = None) -> ChatOpenAI | None:
    """
    Instantiate a LangChain ChatOpenAI client pointing at Nebius Token Factory.
    Returns None if NEBIUS_API_KEY is not configured so nodes can gracefully fall back.
    """
    api_key = settings.nebius_api_key
    if not api_key:
        return None

    model_name = model_override or settings.nebius_model
    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=settings.nebius_base_url,
        temperature=temperature,
        max_tokens=2048,
        timeout=45,
    )
