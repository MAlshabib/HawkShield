"""Saqr -- HawkShield's tool-calling assistant.

The package is layered so that importing any part of it is free of side effects
and never touches the network:

``sqlguard``   read-only SQL guards, dialect handling and row normalisation
``knowledge``  the attack knowledge base, indexed by class
``schemas``    one pydantic argument model per tool (the single schema source)
``tools``      the tool registry: name -> (arg model, executor, flags)
``llm``        the OpenRouter client factory and one ``chat()`` call
``prompts``    the system prompt, per locale and per real SQL dialect
``ratelimit``  a rolling-window call counter
``loop``       the agent loop that ties the above together

Nothing here imports ``backend.app.routers.agent``; the router imports this.
"""
from __future__ import annotations

__all__: list[str] = []
