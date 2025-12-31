"""
AIRS-CP: AI Runtime Security Control Plane

A provider-agnostic AI security gateway that protects LLM applications
with real-time security controls, policy enforcement, and audit logging.
"""

__version__ = "0.1.0"
__author__ = "Jelli"

from airs_cp.config.settings import Settings

__all__ = ["Settings", "__version__"]
