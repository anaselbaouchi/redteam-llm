import os
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    raw: dict


class LLMClient:
    def __init__(self, provider="ollama", model="llama3.2:3b", base_url=None, api_key=None, timeout=120, temperature=0.7):
        self.provider = provider.lower()
        self.model = model
        self.timeout = timeout
        self.api_key = api_key
        self.temperature = temperature  # fixe pour la reproductibilite (voir chat(seed=...))

        # each provider needs a different base url + auth setup
        if self.provider == "ollama":
            self.base_url = base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")

        elif self.provider == "openai":
            self.base_url = base_url or "https://api.openai.com/v1"
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError("missing OPENAI_API_KEY (set it as env var or pass api_key=)")

        elif self.provider == "anthropic":
            self.base_url = base_url or "https://api.anthropic.com/v1"
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError("missing ANTHROPIC_API_KEY (set it as env var or pass api_key=)")

        elif self.provider == "openai_compatible":
            # covers LM Studio, vLLM, text-generation-webui, etc - they all copy OpenAI's format
            if not base_url:
                raise ValueError("openai_compatible needs a base_url, e.g. http://localhost:1234/v1")
            self.base_url = base_url.rstrip("/")
            self.api_key = api_key or "not-needed"

        else:
            raise ValueError(f"don't know this provider: {provider}")

    def chat(self, prompt, system=None, temperature=None, seed=None):
        # temperature: None => defaut de l'instance (0.7). Un juge passe 0.0.
        # seed: None => sampling libre. Un entier => echantillon reproductible
        #   (on passe seed=numero d'essai pour avoir n essais varies ET reproductibles).
        temp = self.temperature if temperature is None else temperature
        if self.provider == "ollama":
            return self._ollama(prompt, system, temp, seed)
        if self.provider == "openai":
            return self._openai_style(prompt, system, "openai", temp, seed)
        if self.provider == "anthropic":
            return self._anthropic(prompt, system, temp)
        if self.provider == "openai_compatible":
            return self._openai_style(prompt, system, "openai_compatible", temp, seed)
        raise ValueError(f"don't know this provider: {self.provider}")

    def is_alive(self):
        # cheap check to see if the target even responds before we bother attacking it
        try:
            if self.provider == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=3)
                return r.status_code == 200

            if self.provider in ("openai", "openai_compatible"):
                headers = {}
                if self.api_key != "not-needed":
                    headers["Authorization"] = f"Bearer {self.api_key}"
                r = requests.get(f"{self.base_url}/models", headers=headers, timeout=3)
                return r.status_code == 200

            if self.provider == "anthropic":
                # no cheap GET endpoint on their side, just sanity check the key looks real
                return bool(self.api_key and self.api_key.startswith("sk-ant-"))
        except requests.RequestException:
            return False

    def _ollama(self, prompt, system, temperature, seed=None):
        options = {"temperature": temperature}
        if seed is not None:
            options["seed"] = seed
        payload = {"model": self.model, "prompt": prompt, "stream": False, "options": options}
        if system:
            payload["system"] = system

        r = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()

        return LLMResponse(data.get("response", ""), "ollama", self.model, data)

    def _openai_style(self, prompt, system, label, temperature, seed=None):
        # same request shape works for real OpenAI and anything OpenAI-compatible
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {"model": self.model, "messages": messages, "temperature": temperature}
        if seed is not None:
            payload["seed"] = seed

        r = requests.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        text = data["choices"][0]["message"]["content"]

        return LLMResponse(text, label, self.model, data)

    def _anthropic(self, prompt, system, temperature):
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 1024,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        r = requests.post(f"{self.base_url}/messages", json=payload, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))

        return LLMResponse(text, "anthropic", self.model, data)


if __name__ == "__main__":
    client = LLMClient(provider="ollama", model="llama3.2:3b")
    print("alive:", client.is_alive())

    resp = client.chat("Why is the sky blue? Answer in one sentence.")
    print(f"[{resp.provider}/{resp.model}] {resp.text}")