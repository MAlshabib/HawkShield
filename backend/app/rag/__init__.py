"""HawkShield RAG package: natural-language Q&A over detected attack packets."""

from backend.app.rag.packet_qa import RagUnavailable, packet_ask

__all__ = ["RagUnavailable", "packet_ask"]
