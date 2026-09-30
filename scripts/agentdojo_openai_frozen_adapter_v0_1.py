"""Frozen single-attempt OpenAI request adapter for AgentDojo clean A/B."""
from typing import Any
MODEL_ID="gpt-4.1-mini-2025-04-14"
TEMPERATURE=0.0
MAX_ATTEMPTS=1

def create_completion_once(*,client:Any,messages,tools):
    return client.chat.completions.create(model=MODEL_ID,messages=messages,tools=list(tools),tool_choice="auto" if tools else None,temperature=TEMPERATURE)
