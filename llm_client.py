import os
import httpx
from typing import Dict, Any, Optional
from models import AIRequest

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


async def call_openai(request: AIRequest, max_tokens: Optional[int] = None) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
        "Content-Type": "application/json",
    }

    payload: Dict[str, Any] = {
        "model": request.model,
        "messages": [m.dict() for m in request.messages],
        "temperature": request.temperature,
    }

    # Hard cap output size (prevents runaway cost)
    if max_tokens is not None:
        payload["max_tokens"] = int(max_tokens)

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(OPENAI_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {}) or {}

    return {
        "content": content,
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        },
        "raw": data,  # keep for debugging (remove later if you want)
    }
