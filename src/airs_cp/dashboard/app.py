"""
AIRS-CP Web Dashboard

A lightweight, modern dashboard using FastAPI + HTMX + TailwindCSS.
No heavy dependencies - just HTML templates with real-time updates.

Features:
- Session Monitor: Real-time request/response stream
- Security Alerts: Detection events with severity indicators
- Taint Lineage: Visual data flow graph
- Metrics: Request volume, detection rates, provider distribution

Usage:
    uvicorn airs_cp.dashboard.app:app --port 8501
"""

import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import asyncio


app = FastAPI(
    title="AIRS-CP Dashboard",
    description="AI Runtime Security Control Plane Dashboard",
    version="0.2.0",
)


# ============================================================================
# HTML Templates (inline for simplicity - no Jinja2 required)
# ============================================================================

def base_template(title: str, content: str, active_tab: str = "monitor") -> str:
    """Base HTML template with navigation."""
    
    def tab_class(tab: str) -> str:
        if tab == active_tab:
            return "bg-cyan-600 text-white"
        return "text-gray-300 hover:bg-gray-700 hover:text-white"
    
    return f'''<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-900">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - AIRS-CP</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://unpkg.com/htmx.org/dist/ext/sse.js"></script>
    <style>
        .severity-low {{ color: #22c55e; }}
        .severity-medium {{ color: #eab308; }}
        .severity-high {{ color: #f97316; }}
        .severity-critical {{ color: #ef4444; font-weight: bold; }}
        .fade-in {{ animation: fadeIn 0.3s ease-in; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        .pulse {{ animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
    </style>
</head>
<body class="h-full">
    <div class="min-h-full">
        <!-- Navigation -->
        <nav class="bg-gray-800">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div class="flex h-16 items-center justify-between">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <span class="text-2xl">🛡️</span>
                        </div>
                        <div class="ml-3">
                            <span class="text-white font-bold text-xl">AIRS-CP</span>
                            <span class="text-gray-400 text-sm ml-2">Control Plane</span>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <div class="flex space-x-4">
                            <a href="/dashboard" class="rounded-md px-3 py-2 text-sm font-medium {tab_class('monitor')}">
                                📊 Monitor
                            </a>
                            <a href="/dashboard/alerts" class="rounded-md px-3 py-2 text-sm font-medium {tab_class('alerts')}">
                                🚨 Alerts
                            </a>
                            <a href="/dashboard/agents" class="rounded-md px-3 py-2 text-sm font-medium {tab_class('agents')}">
                                🤖 Agents
                            </a>
                            <a href="/dashboard/lineage" class="rounded-md px-3 py-2 text-sm font-medium {tab_class('lineage')}">
                                🔗 Lineage
                            </a>
                            <a href="/dashboard/metrics" class="rounded-md px-3 py-2 text-sm font-medium {tab_class('metrics')}">
                                📈 Metrics
                            </a>
                        </div>
                        <div class="ml-6">
                            <span id="status-indicator" class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-green-100 text-green-800">
                                <span class="pulse mr-1">●</span> Live
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
            {content}
        </main>
        
        <!-- Footer -->
        <footer class="bg-gray-800 mt-8">
            <div class="mx-auto max-w-7xl px-4 py-4 text-center text-gray-400 text-sm">
                AIRS-CP v0.2.0 | AI Runtime Security Control Plane
            </div>
        </footer>
    </div>
</body>
</html>'''


def monitor_page() -> str:
    """Session monitor page content."""
    return '''
    <div class="space-y-6">
        <!-- Status Cards -->
        <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <div class="bg-gray-800 rounded-lg p-6">
                <div class="text-gray-400 text-sm">Total Requests</div>
                <div class="text-3xl font-bold text-white" 
                     hx-get="/api/stats/requests" 
                     hx-trigger="load, every 5s">--</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-6">
                <div class="text-gray-400 text-sm">Blocked</div>
                <div class="text-3xl font-bold text-red-500"
                     hx-get="/api/stats/blocked"
                     hx-trigger="load, every 5s">--</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-6">
                <div class="text-gray-400 text-sm">Sanitized</div>
                <div class="text-3xl font-bold text-yellow-500"
                     hx-get="/api/stats/sanitized"
                     hx-trigger="load, every 5s">--</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-6">
                <div class="text-gray-400 text-sm">Mode</div>
                <div class="text-3xl font-bold text-cyan-500"
                     hx-get="/api/stats/mode"
                     hx-trigger="load, every 5s">--</div>
            </div>
        </div>
        
        <!-- Recent Events -->
        <div class="bg-gray-800 rounded-lg">
            <div class="px-6 py-4 border-b border-gray-700">
                <h2 class="text-lg font-medium text-white">Recent Events</h2>
            </div>
            <div id="events-container" 
                 hx-get="/api/events/recent" 
                 hx-trigger="load, every 3s"
                 class="divide-y divide-gray-700 max-h-96 overflow-y-auto">
                <div class="p-6 text-gray-400 text-center">Loading events...</div>
            </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h2 class="text-lg font-medium text-white mb-4">Quick Actions</h2>
            <div class="flex space-x-4">
                <button hx-post="/api/mode/observe" 
                        hx-swap="none"
                        class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm">
                    Set Observe Mode
                </button>
                <button hx-post="/api/mode/enforce"
                        hx-swap="none"
                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-md text-sm">
                    Set Enforce Mode
                </button>
                <button hx-post="/api/kill/toggle"
                        hx-swap="none"
                        class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm">
                    Toggle Kill Switch
                </button>
            </div>
        </div>
    </div>
    '''


def alerts_page() -> str:
    """Security alerts page content."""
    return '''
    <div class="space-y-6">
        <!-- Filter Bar -->
        <div class="bg-gray-800 rounded-lg p-4">
            <div class="flex items-center space-x-4">
                <select class="bg-gray-700 text-white rounded-md px-3 py-2 text-sm" 
                        name="severity"
                        hx-get="/api/alerts"
                        hx-target="#alerts-table"
                        hx-include="[name='detector']"
                        hx-trigger="change">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select class="bg-gray-700 text-white rounded-md px-3 py-2 text-sm" 
                        name="detector"
                        hx-get="/api/alerts"
                        hx-target="#alerts-table"
                        hx-include="[name='severity']"
                        hx-trigger="change">
                    <option value="">All Detectors</option>
                    <option value="pii_detector">PII Detector</option>
                    <option value="injection_detector">Injection Detector</option>
                    <option value="anomaly_detector">Anomaly Detector</option>
                </select>
                <button hx-get="/api/alerts"
                        hx-target="#alerts-table"
                        hx-include="[name='severity'], [name='detector']"
                        class="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-md text-sm">
                    Apply Filter
                </button>
            </div>
        </div>
        
        <!-- Alerts Table -->
        <div class="bg-gray-800 rounded-lg overflow-hidden">
            <table class="min-w-full divide-y divide-gray-700">
                <thead class="bg-gray-700">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Time</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Detector</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Severity</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Confidence</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Action</th>
                    </tr>
                </thead>
                <tbody id="alerts-table" 
                       hx-get="/api/alerts"
                       hx-trigger="load, every 5s"
                       class="divide-y divide-gray-700">
                    <tr><td colspan="5" class="px-6 py-4 text-gray-400 text-center">Loading alerts...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    '''


def lineage_page() -> str:
    """Taint lineage visualization page."""
    return '''
    <div class="space-y-6">
        <!-- Lineage Graph -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h2 class="text-lg font-medium text-white mb-4">Data Lineage Graph</h2>
            <div class="bg-gray-900 rounded-lg p-8 min-h-[400px] flex items-center justify-center">
                <div id="lineage-graph" 
                     hx-get="/api/lineage/graph"
                     hx-trigger="load"
                     class="text-gray-400">
                    Loading lineage graph...
                </div>
            </div>
        </div>
        
        <!-- Taint Details -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Active Taints</h3>
                <div id="active-taints"
                     hx-get="/api/lineage/taints"
                     hx-trigger="load, every 10s"
                     class="space-y-2">
                    <div class="text-gray-400">Loading taints...</div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Sink Violations</h3>
                <div id="sink-violations"
                     hx-get="/api/lineage/violations"
                     hx-trigger="load, every 10s"
                     class="space-y-2">
                    <div class="text-gray-400">Loading violations...</div>
                </div>
            </div>
        </div>
    </div>
    '''


def metrics_page() -> str:
    """Metrics and analytics page."""
    return '''
    <div class="space-y-6">
        <!-- Time Range Selector -->
        <div class="bg-gray-800 rounded-lg p-4">
            <div class="flex items-center space-x-4">
                <span class="text-gray-400 text-sm">Time Range:</span>
                <button class="bg-cyan-600 text-white px-3 py-1 rounded text-sm">1h</button>
                <button class="bg-gray-700 text-gray-300 px-3 py-1 rounded text-sm opacity-50 cursor-not-allowed" title="Coming soon">6h</button>
                <button class="bg-gray-700 text-gray-300 px-3 py-1 rounded text-sm opacity-50 cursor-not-allowed" title="Coming soon">24h</button>
                <button class="bg-gray-700 text-gray-300 px-3 py-1 rounded text-sm opacity-50 cursor-not-allowed" title="Coming soon">7d</button>
                <span class="text-gray-500 text-xs ml-2">(filtering coming soon)</span>
            </div>
        </div>
        
        <!-- Metrics Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Detection Distribution -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Detection Distribution</h3>
                <div id="detection-chart"
                     hx-get="/api/metrics/detections"
                     hx-trigger="load, every 30s"
                     class="h-64 flex items-center justify-center">
                    <div class="text-gray-400">Loading chart...</div>
                </div>
            </div>
            
            <!-- Severity Breakdown -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Severity Breakdown</h3>
                <div id="severity-chart"
                     hx-get="/api/metrics/severity"
                     hx-trigger="load, every 30s"
                     class="h-64 flex items-center justify-center">
                    <div class="text-gray-400">Loading chart...</div>
                </div>
            </div>
            
            <!-- Provider Usage -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Provider Usage</h3>
                <div id="provider-chart"
                     hx-get="/api/metrics/providers"
                     hx-trigger="load, every 30s"
                     class="h-64 flex items-center justify-center">
                    <div class="text-gray-400">Loading chart...</div>
                </div>
            </div>
            
            <!-- Response Times -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">Security Overhead (ms)</h3>
                <div id="latency-chart"
                     hx-get="/api/metrics/latency"
                     hx-trigger="load, every 30s"
                     class="h-64 flex items-center justify-center">
                    <div class="text-gray-400">Loading chart...</div>
                </div>
            </div>
        </div>
    </div>
    '''


def agents_page() -> str:
    """Agent observability page - Tool inventory and invocation tracking."""
    return '''
    <div class="space-y-6">
        <!-- Header with Stats -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-gray-800 rounded-lg p-4">
                <div class="text-gray-400 text-sm">Registered Tools</div>
                <div id="tool-count" 
                     hx-get="/api/agents/stats/tools" 
                     hx-trigger="load, every 10s"
                     class="text-2xl font-bold text-cyan-400">-</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4">
                <div class="text-gray-400 text-sm">Registered Agents</div>
                <div id="agent-count"
                     hx-get="/api/agents/stats/agents"
                     hx-trigger="load, every 10s"
                     class="text-2xl font-bold text-green-400">-</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4">
                <div class="text-gray-400 text-sm">Tool Invocations</div>
                <div id="invocation-count"
                     hx-get="/api/agents/stats/invocations"
                     hx-trigger="load, every 5s"
                     class="text-2xl font-bold text-blue-400">-</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4">
                <div class="text-gray-400 text-sm">Behavioral Deviations</div>
                <div id="deviation-count"
                     hx-get="/api/agents/stats/deviations"
                     hx-trigger="load, every 5s"
                     class="text-2xl font-bold text-red-400">-</div>
            </div>
        </div>
        
        <!-- Two Column Layout -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Tool Inventory -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">🔧 Tool Inventory</h3>
                <div id="tool-inventory"
                     hx-get="/api/agents/tools"
                     hx-trigger="load"
                     class="space-y-2 max-h-96 overflow-y-auto">
                    <div class="text-gray-400">Loading tools...</div>
                </div>
            </div>
            
            <!-- Agent Registry -->
            <div class="bg-gray-800 rounded-lg p-6">
                <h3 class="text-md font-medium text-white mb-4">🤖 Agent Registry</h3>
                <div id="agent-registry"
                     hx-get="/api/agents/list"
                     hx-trigger="load"
                     class="space-y-2 max-h-96 overflow-y-auto">
                    <div class="text-gray-400">Loading agents...</div>
                </div>
            </div>
        </div>
        
        <!-- Recent Invocations with Reasoning -->
        <div class="bg-gray-800 rounded-lg p-6">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-md font-medium text-white">📋 Recent Tool Invocations</h3>
                <span class="text-xs text-gray-500">Shows reasoning for tool selection</span>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Time</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Agent</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Tool</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Reasoning</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Status</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-300 uppercase">Deviation</th>
                        </tr>
                    </thead>
                    <tbody id="invocation-table"
                           hx-get="/api/agents/invocations"
                           hx-trigger="load, every 5s"
                           class="divide-y divide-gray-700">
                        <tr><td colspan="6" class="px-4 py-4 text-gray-400 text-center">Loading invocations...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Deviation Alerts -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h3 class="text-md font-medium text-white mb-4">⚠️ Behavioral Deviation Alerts</h3>
            <div id="deviation-alerts"
                 hx-get="/api/agents/deviations"
                 hx-trigger="load, every 5s"
                 class="space-y-3 max-h-64 overflow-y-auto">
                <div class="text-gray-400">Loading alerts...</div>
            </div>
        </div>
    </div>
    '''


# ============================================================================
# Dashboard Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect root to dashboard."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_home():
    """Dashboard home - Session Monitor."""
    return base_template("Monitor", monitor_page(), "monitor")


@app.get("/dashboard/alerts", response_class=HTMLResponse)
async def dashboard_alerts():
    """Dashboard - Security Alerts."""
    return base_template("Alerts", alerts_page(), "alerts")


@app.get("/dashboard/agents", response_class=HTMLResponse)
async def dashboard_agents():
    """Dashboard - Agent Observability."""
    return base_template("Agents", agents_page(), "agents")


@app.get("/dashboard/lineage", response_class=HTMLResponse)
async def dashboard_lineage():
    """Dashboard - Taint Lineage."""
    return base_template("Lineage", lineage_page(), "lineage")


@app.get("/dashboard/metrics", response_class=HTMLResponse)
async def dashboard_metrics():
    """Dashboard - Metrics."""
    return base_template("Metrics", metrics_page(), "metrics")


# ============================================================================
# API Endpoints for Dashboard
# ============================================================================

def get_gateway_stats():
    """Get stats from gateway via HTTP or from local store."""
    # Try gateway first
    try:
        import httpx
        response = httpx.get("http://localhost:8080/status", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return {
                "total_requests": data.get("stats", {}).get("total_requests", 0),
                "blocked": data.get("stats", {}).get("blocked", 0),
                "sanitized": data.get("stats", {}).get("sanitized", 0),
                "anomalies": data.get("stats", {}).get("anomalies", 0),
                "provider_usage": data.get("stats", {}).get("provider_usage", {}),
                "mode": data.get("mode", "observe"),
                "kill_switch": data.get("kill_switch", False),
            }
    except:
        pass
    
    # Fallback: count from store
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        detections = store.get_recent_detections(limit=1000)
        
        # Count blocked from metadata or high-confidence injection detections
        blocked = 0
        sanitized = 0
        for d in detections:
            if d.detector_name == "pii_detector":
                sanitized += 1
            elif d.detector_name == "injection_detector":
                # Check metadata for blocked flag or use confidence threshold
                meta = d.metadata if isinstance(d.metadata, dict) else {}
                if meta.get("blocked") or d.confidence >= 0.6:
                    blocked += 1
        
        return {
            "total_requests": len(detections),
            "blocked": blocked,
            "sanitized": sanitized,
            "anomalies": 0,
            "provider_usage": {},
            "mode": "unknown",
            "kill_switch": False,
        }
    except:
        pass
    
    return {
        "total_requests": 0,
        "blocked": 0,
        "sanitized": 0,
        "anomalies": 0,
        "provider_usage": {},
        "mode": "observe",
        "kill_switch": False,
    }


@app.get("/api/stats/requests")
async def get_stats_requests():
    stats = get_gateway_stats()
    return HTMLResponse(str(stats["total_requests"]))


@app.get("/api/stats/blocked")
async def get_stats_blocked():
    stats = get_gateway_stats()
    return HTMLResponse(str(stats["blocked"]))


@app.get("/api/stats/sanitized")
async def get_stats_sanitized():
    stats = get_gateway_stats()
    return HTMLResponse(str(stats["sanitized"]))


@app.get("/api/stats/mode")
async def get_stats_mode():
    stats = get_gateway_stats()
    mode = stats["mode"]
    if stats["kill_switch"]:
        return HTMLResponse('<span class="text-red-500">KILL</span>')
    color = "text-green-500" if mode == "observe" else "text-yellow-500"
    return HTMLResponse(f'<span class="{color}">{mode.upper()}</span>')


@app.get("/api/events/recent")
async def get_recent_events():
    """Get recent security events."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        detections = store.get_recent_detections(limit=10)
        
        if not detections:
            return HTMLResponse('<div class="p-6 text-gray-400 text-center">No events yet</div>')
        
        html = ""
        for det in detections:
            severity_class = f"severity-{det.severity.value}"
            html += f'''
            <div class="px-6 py-4 hover:bg-gray-750 fade-in">
                <div class="flex items-center justify-between">
                    <div>
                        <span class="text-white font-medium">{det.detector_name}</span>
                        <span class="{severity_class} ml-2 text-sm">{det.severity.value.upper()}</span>
                    </div>
                    <div class="text-gray-400 text-sm">{det.timestamp[:19]}</div>
                </div>
                <div class="text-gray-400 text-sm mt-1">
                    Confidence: {det.confidence:.0%}
                </div>
            </div>
            '''
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="p-6 text-red-400">Error: {e}</div>')


@app.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None),
    detector: Optional[str] = Query(None),
):
    """Get alerts for table."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        detections = store.get_recent_detections(limit=50)
        
        # Filter
        if severity:
            detections = [d for d in detections if d.severity.value == severity]
        if detector:
            detections = [d for d in detections if d.detector_name == detector]
        
        if not detections:
            return HTMLResponse('<tr><td colspan="5" class="px-6 py-4 text-gray-400 text-center">No alerts found</td></tr>')
        
        html = ""
        for det in detections:
            severity_class = f"severity-{det.severity.value}"
            html += f'''
            <tr class="hover:bg-gray-750">
                <td class="px-6 py-4 text-gray-300 text-sm">{det.timestamp[:19]}</td>
                <td class="px-6 py-4 text-white">{det.detector_name}</td>
                <td class="px-6 py-4 {severity_class}">{det.severity.value.upper()}</td>
                <td class="px-6 py-4 text-gray-300">{det.confidence:.0%}</td>
                <td class="px-6 py-4">
                    <button class="text-cyan-400 hover:text-cyan-300 text-sm">View</button>
                </td>
            </tr>
            '''
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<tr><td colspan="5" class="px-6 py-4 text-red-400">Error: {e}</td></tr>')


@app.get("/api/lineage/graph")
async def get_lineage_graph():
    """Get lineage graph visualization."""
    # Simple ASCII art for now - could use D3.js or Mermaid
    graph = '''
    <pre class="text-cyan-400 text-sm">
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │ User Input  │────▶│   Model     │────▶│  Response   │
    │ (RESTRICTED)│     │ Processing  │     │   (taint)   │
    └─────────────┘     └─────────────┘     └─────────────┘
           │                   │                   │
           │                   ▼                   │
           │            ┌─────────────┐            │
           │            │  RAG Docs   │            │
           │            │ (INTERNAL)  │            │
           │            └─────────────┘            │
           │                                       │
           └───────────────────────────────────────┘
                    Taint Propagation Flow
    </pre>
    <p class="text-gray-400 text-sm mt-4">
        Data lineage shows how sensitivity levels propagate through the system.
        Restricted data cannot flow to external tools or storage.
    </p>
    '''
    return HTMLResponse(graph)


@app.get("/api/lineage/taints")
async def get_active_taints():
    """Get active taints."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        
        # Get recent taint labels
        taints = store.get_recent_taints(limit=10) if hasattr(store, 'get_recent_taints') else []
        
        if not taints:
            return HTMLResponse('''
            <div class="text-gray-500 text-sm">
                <div class="flex items-center justify-between py-2">
                    <span>user_input:pii</span>
                    <span class="text-red-400">RESTRICTED</span>
                </div>
                <div class="flex items-center justify-between py-2">
                    <span>rag_doc:policy</span>
                    <span class="text-yellow-400">INTERNAL</span>
                </div>
                <div class="flex items-center justify-between py-2">
                    <span>system_prompt</span>
                    <span class="text-green-400">PUBLIC</span>
                </div>
            </div>
            ''')
        
        html = '<div class="space-y-2">'
        for t in taints:
            html += f'<div class="flex justify-between py-2 text-sm"><span class="text-gray-300">{t.label}</span><span>{t.sensitivity.value}</span></div>'
        html += '</div>'
        return HTMLResponse(html)
    except:
        return HTMLResponse('<div class="text-gray-500">No taints tracked</div>')


@app.get("/api/lineage/violations")
async def get_sink_violations():
    """Get sink violations."""
    return HTMLResponse('''
    <div class="text-sm">
        <div class="flex items-center py-2 text-red-400">
            <span class="mr-2">⛔</span>
            <span>Blocked: RESTRICTED data to external tool</span>
        </div>
        <div class="flex items-center py-2 text-yellow-400">
            <span class="mr-2">⚠️</span>
            <span>Warning: CONFIDENTIAL data in response</span>
        </div>
    </div>
    ''')


@app.get("/api/metrics/detections")
async def get_detection_metrics():
    """Get detection distribution chart from actual data."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        detections = store.get_recent_detections(limit=100)
        
        # Count by detector type
        pii_count = sum(1 for d in detections if 'pii' in d.detector_name.lower())
        injection_count = sum(1 for d in detections if 'injection' in d.detector_name.lower())
        anomaly_count = sum(1 for d in detections if 'anomaly' in d.detector_name.lower())
        
        # Calculate heights (max 120px)
        max_count = max(pii_count, injection_count, anomaly_count, 1)
        pii_height = int((pii_count / max_count) * 120) if max_count > 0 else 10
        inj_height = int((injection_count / max_count) * 120) if max_count > 0 else 10
        anom_height = int((anomaly_count / max_count) * 120) if max_count > 0 else 10
        
        return HTMLResponse(f'''
        <div class="w-full">
            <div class="flex items-end justify-around h-48 px-4">
                <div class="flex flex-col items-center">
                    <div class="bg-cyan-500 w-16 rounded-t" style="height: {pii_height}px;"></div>
                    <span class="text-gray-400 text-xs mt-2">PII</span>
                    <span class="text-white text-sm">{pii_count}</span>
                </div>
                <div class="flex flex-col items-center">
                    <div class="bg-red-500 w-16 rounded-t" style="height: {inj_height}px;"></div>
                    <span class="text-gray-400 text-xs mt-2">Injection</span>
                    <span class="text-white text-sm">{injection_count}</span>
                </div>
                <div class="flex flex-col items-center">
                    <div class="bg-yellow-500 w-16 rounded-t" style="height: {anom_height}px;"></div>
                    <span class="text-gray-400 text-xs mt-2">Anomaly</span>
                    <span class="text-white text-sm">{anomaly_count}</span>
                </div>
            </div>
        </div>
        ''')
    except Exception as e:
        return HTMLResponse(f'<div class="text-red-400">Error: {e}</div>')


@app.get("/api/metrics/severity")
async def get_severity_metrics():
    """Get severity breakdown from actual data."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        detections = store.get_recent_detections(limit=100)
        
        total = len(detections) or 1
        low = sum(1 for d in detections if d.severity.value == 'low')
        medium = sum(1 for d in detections if d.severity.value == 'medium')
        high = sum(1 for d in detections if d.severity.value == 'high')
        critical = sum(1 for d in detections if d.severity.value == 'critical')
        
        low_pct = int((low / total) * 100)
        med_pct = int((medium / total) * 100)
        high_pct = int((high / total) * 100)
        crit_pct = int((critical / total) * 100)
        
        return HTMLResponse(f'''
        <div class="space-y-3">
            <div>
                <div class="flex justify-between text-sm mb-1">
                    <span class="text-green-400">Low ({low})</span>
                    <span class="text-gray-400">{low_pct}%</span>
                </div>
                <div class="w-full bg-gray-700 rounded-full h-2">
                    <div class="bg-green-500 h-2 rounded-full" style="width: {low_pct}%"></div>
                </div>
            </div>
            <div>
                <div class="flex justify-between text-sm mb-1">
                    <span class="text-yellow-400">Medium ({medium})</span>
                    <span class="text-gray-400">{med_pct}%</span>
                </div>
                <div class="w-full bg-gray-700 rounded-full h-2">
                    <div class="bg-yellow-500 h-2 rounded-full" style="width: {med_pct}%"></div>
                </div>
            </div>
            <div>
                <div class="flex justify-between text-sm mb-1">
                    <span class="text-orange-400">High ({high})</span>
                    <span class="text-gray-400">{high_pct}%</span>
                </div>
                <div class="w-full bg-gray-700 rounded-full h-2">
                    <div class="bg-orange-500 h-2 rounded-full" style="width: {high_pct}%"></div>
                </div>
            </div>
            <div>
                <div class="flex justify-between text-sm mb-1">
                    <span class="text-red-400">Critical ({critical})</span>
                    <span class="text-gray-400">{crit_pct}%</span>
                </div>
                <div class="w-full bg-gray-700 rounded-full h-2">
                    <div class="bg-red-500 h-2 rounded-full" style="width: {crit_pct}%"></div>
                </div>
            </div>
        </div>
        ''')
    except Exception as e:
        return HTMLResponse(f'<div class="text-red-400">Error: {e}</div>')


@app.get("/api/metrics/providers")
async def get_provider_metrics():
    """Get provider usage."""
    # Get actual provider stats from gateway
    stats = get_gateway_stats()
    provider_usage = stats.get("provider_usage", {})
    
    total = sum(provider_usage.values()) if provider_usage else 0
    
    if total == 0:
        # No data yet - show placeholder
        return HTMLResponse('''
        <div class="flex items-center justify-center h-full">
            <div class="text-gray-400 text-center">
                <p>No provider data yet</p>
                <p class="text-sm mt-2">Run some requests through the gateway</p>
            </div>
        </div>
        ''')
    
    # Calculate percentages
    ollama_pct = int(provider_usage.get("ollama", 0) / total * 100) if total > 0 else 0
    openai_pct = int(provider_usage.get("openai", 0) / total * 100) if total > 0 else 0
    anthropic_pct = int(provider_usage.get("anthropic", 0) / total * 100) if total > 0 else 0
    azure_pct = int(provider_usage.get("azure", 0) / total * 100) if total > 0 else 0
    
    # Only show providers that have been used
    providers_html = ""
    
    if provider_usage.get("ollama", 0) > 0:
        providers_html += f'''
            <div class="bg-gray-700 rounded-lg p-4 text-center">
                <div class="text-2xl mb-1">🦙</div>
                <div class="text-white font-medium">Ollama</div>
                <div class="text-cyan-400 text-2xl font-bold">{ollama_pct}%</div>
                <div class="text-gray-400 text-sm">{provider_usage.get("ollama", 0)} requests</div>
            </div>
        '''
    
    if provider_usage.get("openai", 0) > 0:
        providers_html += f'''
            <div class="bg-gray-700 rounded-lg p-4 text-center">
                <div class="text-2xl mb-1">🤖</div>
                <div class="text-white font-medium">OpenAI</div>
                <div class="text-green-400 text-2xl font-bold">{openai_pct}%</div>
                <div class="text-gray-400 text-sm">{provider_usage.get("openai", 0)} requests</div>
            </div>
        '''
    
    if provider_usage.get("anthropic", 0) > 0:
        providers_html += f'''
            <div class="bg-gray-700 rounded-lg p-4 text-center">
                <div class="text-2xl mb-1">🅰️</div>
                <div class="text-white font-medium">Anthropic</div>
                <div class="text-purple-400 text-2xl font-bold">{anthropic_pct}%</div>
                <div class="text-gray-400 text-sm">{provider_usage.get("anthropic", 0)} requests</div>
            </div>
        '''
    
    if provider_usage.get("azure", 0) > 0:
        providers_html += f'''
            <div class="bg-gray-700 rounded-lg p-4 text-center">
                <div class="text-2xl mb-1">☁️</div>
                <div class="text-white font-medium">Azure</div>
                <div class="text-blue-400 text-2xl font-bold">{azure_pct}%</div>
                <div class="text-gray-400 text-sm">{provider_usage.get("azure", 0)} requests</div>
            </div>
        '''
    
    if not providers_html:
        providers_html = '<div class="text-gray-400">No providers used yet</div>'
    
    return HTMLResponse(f'''
    <div class="flex items-center justify-center h-full">
        <div class="grid grid-cols-2 gap-4 w-full">
            {providers_html}
        </div>
    </div>
    ''')


@app.get("/api/metrics/latency")
async def get_latency_metrics():
    """Get latency metrics from gateway."""
    try:
        import httpx
        response = httpx.get("http://localhost:8080/status", timeout=2)
        data = response.json()
        latencies = data.get("stats", {}).get("latencies", {})
        
        pii_ms = latencies.get("pii_ms", 0)
        injection_ms = latencies.get("injection_ms", 0)
        ml_ms = latencies.get("ml_ms", 0)
        total_ms = latencies.get("total_ms", 0)
        
        # Calculate percentages for progress bars (max 20ms target)
        pii_pct = min(pii_ms / 20 * 100, 100)
        injection_pct = min(injection_ms / 20 * 100, 100)
        ml_pct = min(ml_ms / 20 * 100, 100)
        total_pct = min(total_ms / 20 * 100, 100)
        
        # Color based on value
        def color(ms):
            if ms < 5:
                return "green"
            elif ms < 10:
                return "yellow"
            else:
                return "red"
        
        return HTMLResponse(f'''
        <div class="space-y-4">
            <div class="flex items-center">
                <span class="text-gray-400 w-24 text-sm">PII Scan</span>
                <div class="flex-1 bg-gray-700 rounded-full h-4 mx-4">
                    <div class="bg-{color(pii_ms)}-500 h-4 rounded-full" style="width: {pii_pct}%"></div>
                </div>
                <span class="text-{color(pii_ms)}-400 text-sm">{pii_ms:.1f}ms</span>
            </div>
            <div class="flex items-center">
                <span class="text-gray-400 w-24 text-sm">Injection</span>
                <div class="flex-1 bg-gray-700 rounded-full h-4 mx-4">
                    <div class="bg-{color(injection_ms)}-500 h-4 rounded-full" style="width: {injection_pct}%"></div>
                </div>
                <span class="text-{color(injection_ms)}-400 text-sm">{injection_ms:.1f}ms</span>
            </div>
            <div class="flex items-center">
                <span class="text-gray-400 w-24 text-sm">ML Models</span>
                <div class="flex-1 bg-gray-700 rounded-full h-4 mx-4">
                    <div class="bg-{color(ml_ms)}-500 h-4 rounded-full" style="width: {ml_pct}%"></div>
                </div>
                <span class="text-{color(ml_ms)}-400 text-sm">{ml_ms:.1f}ms</span>
            </div>
            <div class="flex items-center">
                <span class="text-gray-400 w-24 text-sm">Total</span>
                <div class="flex-1 bg-gray-700 rounded-full h-4 mx-4">
                    <div class="bg-cyan-500 h-4 rounded-full" style="width: {total_pct}%"></div>
                </div>
                <span class="text-cyan-400 text-sm">{total_ms:.1f}ms</span>
            </div>
            <p class="text-gray-500 text-xs mt-4">
                Average security overhead per request. Target: &lt;20ms
            </p>
        </div>
        ''')
    except Exception as e:
        return HTMLResponse(f'''
        <div class="text-gray-500 text-center py-4">
            <p>Unable to fetch latency metrics</p>
            <p class="text-xs mt-2">Gateway may not be running</p>
        </div>
        ''')


@app.post("/api/mode/{mode}")
async def set_mode(mode: str):
    """Set runtime mode via gateway."""
    try:
        import httpx
        response = httpx.post(f"http://localhost:8080/mode", json={"mode": mode}, timeout=2)
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/kill/toggle")
async def toggle_kill_switch():
    """Toggle kill switch via gateway."""
    try:
        import httpx
        # Check current state
        status_response = httpx.get("http://localhost:8080/status", timeout=2)
        current_state = status_response.json().get("kill_switch", False)
        
        # Toggle
        if current_state:
            response = httpx.delete("http://localhost:8080/kill", timeout=2)
        else:
            response = httpx.post("http://localhost:8080/kill", timeout=2)
        
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# Agent Observability API Endpoints
# ============================================================================

@app.get("/api/agents/stats/tools")
async def get_agent_stats_tools():
    """Get tool count."""
    try:
        from airs_cp.observability.registry import get_registry
        registry = get_registry()
        return HTMLResponse(str(len(registry.list_tools())))
    except:
        return HTMLResponse("0")


@app.get("/api/agents/stats/agents")
async def get_agent_stats_agents():
    """Get agent count."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        agents = store.get_agent_registrations()
        return HTMLResponse(str(len(agents)))
    except:
        return HTMLResponse("0")


@app.get("/api/agents/stats/invocations")
async def get_agent_stats_invocations():
    """Get invocation count."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        stats = store.get_invocation_stats()
        return HTMLResponse(str(stats.get("total", 0)))
    except:
        return HTMLResponse("0")


@app.get("/api/agents/stats/deviations")
async def get_agent_stats_deviations():
    """Get deviation count."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        stats = store.get_invocation_stats()
        return HTMLResponse(str(stats.get("deviations", 0)))
    except:
        return HTMLResponse("0")


@app.get("/api/agents/tools")
async def get_agent_tools():
    """Get tool inventory."""
    try:
        from airs_cp.observability.registry import get_registry
        registry = get_registry()
        tools = registry.list_tools()
        
        if not tools:
            return HTMLResponse('<div class="text-gray-500">No tools registered</div>')
        
        html = ""
        for tool in tools:
            risk_color = {
                "low": "green",
                "medium": "yellow", 
                "high": "orange",
                "critical": "red"
            }.get(tool.risk_level.value, "gray")
            
            external_badge = '<span class="text-xs bg-blue-900 text-blue-300 px-1 rounded">external</span>' if tool.can_access_external else ''
            approval_badge = '<span class="text-xs bg-purple-900 text-purple-300 px-1 rounded">approval</span>' if tool.requires_approval else ''
            
            html += f'''
            <div class="bg-gray-700 rounded p-3 mb-2">
                <div class="flex justify-between items-start">
                    <div>
                        <span class="font-medium text-white">{tool.name}</span>
                        <span class="text-xs text-gray-400 ml-2">{tool.id}</span>
                    </div>
                    <span class="text-xs px-2 py-0.5 rounded bg-{risk_color}-900 text-{risk_color}-300">
                        {tool.risk_level.value}
                    </span>
                </div>
                <p class="text-gray-400 text-sm mt-1">{tool.description}</p>
                <div class="flex gap-2 mt-2">
                    <span class="text-xs bg-gray-600 text-gray-300 px-1 rounded">{tool.category.value}</span>
                    {external_badge}
                    {approval_badge}
                </div>
            </div>
            '''
        
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="text-red-400">Error: {e}</div>')


@app.get("/api/agents/list")
async def get_agent_list():
    """Get agent registry."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        agents = store.get_agent_registrations()
        
        if not agents:
            return HTMLResponse('''
            <div class="text-gray-500 text-center py-4">
                <p>No agents registered</p>
                <p class="text-xs mt-2">Run the enterprise agent sample (06_enterprise_agent.py)</p>
            </div>
            ''')
        
        html = ""
        for agent in agents:
            tools = agent.get("allowed_tools", [])
            tools_str = ", ".join(tools[:3]) if tools else ""
            if len(tools) > 3:
                tools_str += f" +{len(tools) - 3} more"
            
            html += f'''
            <div class="bg-gray-700 rounded p-3 mb-2">
                <div class="flex justify-between items-start">
                    <div>
                        <span class="font-medium text-white">{agent.get("name", "Unknown")}</span>
                        <span class="text-xs text-gray-400 ml-2">{agent.get("id", "")}</span>
                    </div>
                    <span class="text-xs px-2 py-0.5 rounded bg-cyan-900 text-cyan-300">
                        {agent.get("risk_tolerance", "medium")} risk
                    </span>
                </div>
                <p class="text-gray-400 text-sm mt-1">{agent.get("purpose", "")}</p>
                <div class="text-xs text-gray-500 mt-2">
                    Tools: {tools_str if tools_str else "any"}
                </div>
            </div>
            '''
        
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="text-red-400">Error: {e}</div>')


@app.get("/api/agents/invocations")
async def get_agent_invocations():
    """Get recent tool invocations with reasoning."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        invocations = store.get_recent_invocations(limit=20)
        
        if not invocations:
            return HTMLResponse('''
            <tr>
                <td colspan="6" class="px-4 py-8 text-gray-500 text-center">
                    <p>No tool invocations recorded yet</p>
                    <p class="text-xs mt-2">Run the enterprise agent sample (06_enterprise_agent.py)</p>
                </td>
            </tr>
            ''')
        
        html = ""
        for inv in invocations:
            # Format timestamp
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(inv["timestamp"].replace("Z", ""))
                time_str = ts.strftime("%H:%M:%S")
            except:
                time_str = str(inv.get("timestamp", ""))[:8]
            
            # Status badge
            status = inv.get("status", "success")
            status_colors = {
                "success": ("green", "✓"),
                "failed": ("red", "✗"),
                "blocked": ("red", "⛔"),
                "pending": ("yellow", "⏳"),
            }
            color, icon = status_colors.get(status, ("gray", "?"))
            
            # Deviation indicator
            deviation_score = inv.get("deviation_score", 0)
            if deviation_score > 0.7:
                deviation_html = f'<span class="text-red-400 font-bold">{deviation_score:.0%}</span>'
            elif deviation_score > 0.3:
                deviation_html = f'<span class="text-yellow-400">{deviation_score:.0%}</span>'
            else:
                deviation_html = '<span class="text-green-400">Normal</span>'
            
            # Truncate reasoning
            reasoning = inv.get("reasoning", "")
            full_reasoning = reasoning
            if len(reasoning) > 60:
                reasoning = reasoning[:60] + "..."
            if not reasoning:
                reasoning = '<span class="text-gray-500 italic">No reasoning provided</span>'
                full_reasoning = ""
            
            agent_id = inv.get("agent_id", "") or "-"
            tool_id = inv.get("tool_id", "")
            
            html += f'''
            <tr class="hover:bg-gray-750">
                <td class="px-4 py-3 text-sm text-gray-400">{time_str}</td>
                <td class="px-4 py-3 text-sm text-cyan-400">{agent_id}</td>
                <td class="px-4 py-3 text-sm text-white">{tool_id}</td>
                <td class="px-4 py-3 text-sm text-gray-300" title="{full_reasoning}">{reasoning}</td>
                <td class="px-4 py-3 text-sm text-{color}-400">{icon} {status}</td>
                <td class="px-4 py-3 text-sm">{deviation_html}</td>
            </tr>
            '''
        
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<tr><td colspan="6" class="px-4 py-4 text-red-400">Error: {e}</td></tr>')


@app.get("/api/agents/deviations")
async def get_agent_deviations():
    """Get behavioral deviation alerts."""
    try:
        from airs_cp.store.database import get_store
        store = get_store()
        deviations = store.get_invocations_with_deviations(min_score=0.3)
        
        if not deviations:
            return HTMLResponse('''
            <div class="text-gray-500 text-center py-4">
                <p>✓ No behavioral deviations detected</p>
                <p class="text-xs mt-2">All agent tool calls are within expected patterns</p>
            </div>
            ''')
        
        html = ""
        for inv in deviations[-10:]:  # Last 10
            deviation_score = inv.get("deviation_score", 0)
            severity_color = "red" if deviation_score > 0.7 else "yellow"
            deviation_reasons = inv.get("deviation_reasons", [])
            reasons = ", ".join(deviation_reasons) if deviation_reasons else "Unusual pattern"
            tool_id = inv.get("tool_id", "unknown")
            agent_id = inv.get("agent_id", "") or "unknown"
            
            html += f'''
            <div class="bg-{severity_color}-900/20 border border-{severity_color}-700 rounded p-3 mb-2">
                <div class="flex justify-between items-start">
                    <div class="flex items-center gap-2">
                        <span class="text-{severity_color}-400">⚠️</span>
                        <span class="font-medium text-white">{tool_id}</span>
                        <span class="text-gray-400 text-sm">by {agent_id}</span>
                    </div>
                    <span class="text-{severity_color}-400 font-bold">{deviation_score:.0%}</span>
                </div>
                <p class="text-gray-300 text-sm mt-1">{reasons}</p>
            </div>
            '''
        
        return HTMLResponse(html)
    except Exception as e:
        return HTMLResponse(f'<div class="text-red-400">Error: {e}</div>')


# ============================================================================
# Main
# ============================================================================

def run_dashboard(host: str = "0.0.0.0", port: int = 8501):
    """Run the dashboard server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
