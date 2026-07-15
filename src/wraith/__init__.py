"""wraith -- SSRF detection and out-of-band confirmation for the cloud-metadata, protocol-smuggling, and MCP attack surface."""

from __future__ import annotations

__version__ = "0.9.2"

from wraith.findings import Finding

__all__ = ["Finding", "__version__"]
