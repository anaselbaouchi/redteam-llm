"""
Client LLM unifie, agnostique du fournisseur.

L'idee: la grande majorite des APIs parlent le format OpenAI (/chat/completions).
Donc au lieu d'une branche par fournisseur, on a:
  - un REGISTRE (PROVIDERS): une entree de config par fournisseur (donnee pure).
  - quelques adaptateurs de FORMAT (5): openai, anthropic, ollama, cohere, bedrock.
Ajouter un fournisseur compatible OpenAI = une ligne dans le registre, pas de code.

L'interface publique (chat, is_alive, LLMResponse) ne change pas: les modules
LLM01/02/06/10 continuent de marcher sans modification.
"""

import os
import time
import requests
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    raw: dict


@dataclass
class ProviderConfig:
    format: str                       # openai | anthropic | ollama | cohere | bedrock
    base_url: str = ""
    api_key_env: Optional[str] = None
    auth: str = "bearer"              # bearer | api-key-header | x-api-key | none
    extra_headers: dict = field(default_factory=dict)
    default_model: Optional[str] = None
    supports_seed: bool = False
    aliases: tuple = ()


# ---------------------------------------------------------------------------
# REGISTRE : ajouter un fournisseur compatible OpenAI = une ligne ici.
# ---------------------------------------------------------------------------

PROVIDERS = {
    # --- cloud / commercial ---
    "openai": ProviderConfig("openai", "https://api.openai.com/v1", "OPENAI_API_KEY",
                             default_model="gpt-4o-mini", supports_seed=True),
    "anthropic": ProviderConfig("anthropic", "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY",
                                auth="x-api-key", default_model="claude-3-5-sonnet-latest",
                                aliases=("claude",)),
    "gemini": ProviderConfig("openai", "https://generativelanguage.googleapis.com/v1beta/openai",
                             "GEMINI_API_KEY", default_model="gemini-flash-latest", aliases=("google",)),
    "azure": ProviderConfig("openai", "", "AZURE_OPENAI_API_KEY", auth="api-key-header"),
    "mistral": ProviderConfig("openai", "https://api.mistral.ai/v1", "MISTRAL_API_KEY",
                              default_model="mistral-small-latest"),
    "cohere": ProviderConfig("cohere", "https://api.cohere.com/v2", "COHERE_API_KEY",
                             default_model="command-r"),
    "groq": ProviderConfig("openai", "https://api.groq.com/openai/v1", "GROQ_API_KEY",
                           default_model="llama-3.3-70b-versatile"),
    "together": ProviderConfig("openai", "https://api.together.xyz/v1", "TOGETHER_API_KEY"),
    "fireworks": ProviderConfig("openai", "https://api.fireworks.ai/inference/v1", "FIREWORKS_API_KEY"),
    "deepseek": ProviderConfig("openai", "https://api.deepseek.com/v1", "DEEPSEEK_API_KEY",
                               default_model="deepseek-chat"),
    "xai": ProviderConfig("openai", "https://api.x.ai/v1", "XAI_API_KEY",
                          default_model="grok-2-latest", aliases=("grok",)),
    "perplexity": ProviderConfig("openai", "https://api.perplexity.ai", "PERPLEXITY_API_KEY",
                                 aliases=("pplx",)),
    "openrouter": ProviderConfig("openai", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "nvidia": ProviderConfig("openai", "https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY",
                             aliases=("nim",)),
    "huggingface": ProviderConfig("openai", "https://router.huggingface.co/v1", "HF_TOKEN",
                                  aliases=("hf",)),
    "bedrock": ProviderConfig("bedrock", "", None, auth="none",
                              default_model="anthropic.claude-3-5-sonnet-20240620-v1:0"),

    # --- local / auto-heberge ---
    "ollama": ProviderConfig("ollama", "http://localhost:11434", None, auth="none",
                             default_model="llama3.2:3b", supports_seed=True),
    "lmstudio": ProviderConfig("openai", "http://localhost:1234/v1", None, auth="none",
                               supports_seed=True),
    "vllm": ProviderConfig("openai", "http://localhost:8000/v1", None, auth="none",
                           supports_seed=True),
    "llamacpp": ProviderConfig("openai", "http://localhost:8080/v1", None, auth="none",
                               supports_seed=True, aliases=("llama_cpp",)),

    # --- echappatoire generique: n'importe quel endpoint compatible OpenAI ---
    "openai_compatible": ProviderConfig("openai", "", None, auth="bearer", supports_seed=True),
}

# aliases -> nom canonique
_ALIASES = {a: name for name, cfg in PROVIDERS.items() for a in cfg.aliases}


def resolve_provider(name: str) -> tuple:
    key = (name or "").lower()
    key = _ALIASES.get(key, key)
    if key not in PROVIDERS:
        raise ValueError(f"fournisseur inconnu: {name}. Connus: {', '.join(sorted(PROVIDERS))}")
    return key, PROVIDERS[key]


# ---------------------------------------------------------------------------
# CLIENT
# ---------------------------------------------------------------------------

class LLMClient:
    def __init__(self, provider="ollama", model=None, base_url=None, api_key=None,
                 timeout=120, temperature=0.7, max_retries=3):
        self.provider, self.config = resolve_provider(provider)
        self.format = self.config.format
        self.model = model or self.config.default_model
        if not self.model:
            raise ValueError(f"aucun modele: passe model= pour le fournisseur '{self.provider}'")
        self.timeout = timeout
        self.temperature = temperature  # fixe pour la reproductibilite (voir chat(seed=...))
        self.max_retries = max_retries

        self.base_url = (base_url or self.config.base_url or "").rstrip("/")
        env = self.config.api_key_env
        self.api_key = api_key or (os.getenv(env) if env else None)

        # un endpoint compatible OpenAI sans URL n'est pas utilisable
        if self.format in ("openai", "cohere") and not self.base_url:
            raise ValueError(f"'{self.provider}' a besoin d'un base_url (passe base_url=...)")
        # une API cloud a besoin de sa cle
        if self.config.auth != "none" and not self.api_key:
            hint = f"({env})" if env else ""
            raise ValueError(f"cle API manquante pour '{self.provider}' {hint}: "
                             f"definis la variable d'env ou passe api_key=")

    # -- API publique (inchangee) --------------------------------------------

    def chat(self, prompt, system=None, temperature=None, seed=None):
        # temperature: None => defaut de l'instance (0.7). Un juge passe 0.0.
        # seed: None => sampling libre. Un entier => echantillon reproductible,
        #   ignore par les fournisseurs qui ne le supportent pas.
        temp = self.temperature if temperature is None else temperature
        adapter = _ADAPTERS[self.format]
        return adapter(self, prompt, system, temp, seed)

    def is_alive(self):
        # verif rapide que la cible repond, avant de l'attaquer
        try:
            if self.format == "ollama":
                return requests.get(f"{self.base_url}/api/tags", timeout=3).status_code == 200
            if self.format == "openai":
                r = requests.get(f"{self.base_url}/models", headers=self._headers(), timeout=5)
                return r.ok
            if self.format == "anthropic":
                return bool(self.api_key)
            if self.format == "cohere":
                return bool(self.api_key)
            if self.format == "bedrock":
                return True  # pas de ping simple; on tente directement
        except requests.RequestException:
            return False
        return False

    # -- plomberie interne ---------------------------------------------------

    def _headers(self) -> dict:
        h = dict(self.config.extra_headers)
        if self.config.auth == "bearer" and self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        elif self.config.auth == "api-key-header" and self.api_key:
            h["api-key"] = self.api_key
        elif self.config.auth == "x-api-key" and self.api_key:
            h["x-api-key"] = self.api_key
        return h

    def _post(self, url, payload, headers=None):
        # une seule couche de retry/backoff pour tous les fournisseurs (429, 5xx)
        headers = headers or self._headers()
        wait = 1.0
        for attempt in range(self.max_retries + 1):
            r = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                retry_after = r.headers.get("Retry-After")
                time.sleep(float(retry_after) if retry_after else wait)
                wait *= 2
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# ADAPTATEURS DE FORMAT (un par format de fil, pas par fournisseur)
# ---------------------------------------------------------------------------

def _adapt_ollama(client, prompt, system, temperature, seed):
    options = {"temperature": temperature}
    if seed is not None:
        options["seed"] = seed
    payload = {"model": client.model, "prompt": prompt, "stream": False, "options": options}
    if system:
        payload["system"] = system
    data = client._post(f"{client.base_url}/api/generate", payload, headers={})
    return LLMResponse(data.get("response", ""), client.provider, client.model, data)


def _adapt_openai(client, prompt, system, temperature, seed):
    # meme forme de requete pour OpenAI et tout ce qui est compatible OpenAI
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": client.model, "messages": messages, "temperature": temperature}
    if seed is not None and client.config.supports_seed:
        payload["seed"] = seed
    data = client._post(f"{client.base_url}/chat/completions", payload)
    text = data["choices"][0]["message"]["content"]
    return LLMResponse(text, client.provider, client.model, data)


def _adapt_anthropic(client, prompt, system, temperature, seed):
    headers = client._headers()
    headers["anthropic-version"] = "2023-06-01"
    headers["content-type"] = "application/json"
    payload = {
        "model": client.model,
        "max_tokens": 1024,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system
    data = client._post(f"{client.base_url}/messages", payload, headers=headers)
    text = "".join(block.get("text", "") for block in data.get("content", []))
    return LLMResponse(text, client.provider, client.model, data)


def _adapt_cohere(client, prompt, system, temperature, seed):
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": client.model, "messages": messages, "temperature": temperature}
    data = client._post(f"{client.base_url}/chat", payload)
    # Cohere v2: message.content est une liste de blocs {type, text}
    blocks = data.get("message", {}).get("content", [])
    text = "".join(b.get("text", "") for b in blocks)
    return LLMResponse(text, client.provider, client.model, data)


def _adapt_bedrock(client, prompt, system, temperature, seed):
    # SigV4 -> on delegue a boto3, importe seulement si on utilise vraiment Bedrock
    try:
        import boto3
    except ImportError:
        raise RuntimeError("Bedrock a besoin de boto3 (pip install boto3), "
                           "ou route le modele via 'openrouter' pour eviter SigV4.")
    rt = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"))
    kwargs = {
        "modelId": client.model,
        "messages": [{"role": "user", "content": [{"text": prompt}]}],
        "inferenceConfig": {"temperature": temperature},
    }
    if system:
        kwargs["system"] = [{"text": system}]
    resp = rt.converse(**kwargs)
    text = resp["output"]["message"]["content"][0]["text"]
    return LLMResponse(text, client.provider, client.model, resp)


_ADAPTERS = {
    "ollama": _adapt_ollama,
    "openai": _adapt_openai,
    "anthropic": _adapt_anthropic,
    "cohere": _adapt_cohere,
    "bedrock": _adapt_bedrock,
}


if __name__ == "__main__":
    client = LLMClient(provider="ollama", model="llama3.2:3b")
    print("alive:", client.is_alive())
    resp = client.chat("Why is the sky blue? Answer in one sentence.")
    print(f"[{resp.provider}/{resp.model}] {resp.text}")
