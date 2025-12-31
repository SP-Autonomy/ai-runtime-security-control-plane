"""
AIRS-CP Dashboard Module

Provides a web-based dashboard for monitoring and managing
the AI Runtime Security Control Plane.
"""

from airs_cp.dashboard.app import app, run_dashboard

__all__ = ["app", "run_dashboard"]
