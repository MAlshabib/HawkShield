"""Attack knowledge base.

This package used to hold ``packet_qa.py``, the text-to-SQL RAG behind
``POST /ask``.  That was replaced by the Saqr agent (``backend/app/agent/``) and
removed; ``/ask`` is now a thin shim over the same loop that serves
``/agent/ask``.

What remains is ``knowledge/attacks.md``, and it stays at this path on purpose:
``ATTACKS_FILE`` in ``.env.example`` and in the Pi's live ``.env`` both point
here, and ``backend/app/agent/knowledge.py`` resolves it relative to this
package rather than the working directory.  Moving the file would break a
deployed configuration for no gain.
"""

__all__: list[str] = []
