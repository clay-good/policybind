"""
HTTP server module for PolicyBind.

This module provides an HTTP API server for PolicyBind that can be deployed
as a service. It uses aiohttp for async HTTP handling and provides a
complete REST API for policy enforcement, model registry management,
token management, and incident tracking.

The server is optional - PolicyBind works as a library without running
the server. To use the server, install the 'server' extra:

    pip install policybind[server]

Example:
    Running the server::

        from policybind.server import create_app, run_server
        from policybind.config import PolicyBindConfig

        config = PolicyBindConfig()
        app = create_app(config)
        run_server(app, host="0.0.0.0", port=8080)

    Or from the command line::

        policybind serve --host 0.0.0.0 --port 8080

Components:
    - app: Application factory and runner
    - routes: API route definitions
    - auth: API authentication and authorization
    - middleware: HTTP middleware (logging, error handling, etc.)
"""

from policybind.server.app import PolicyBindApplication, create_app, run_server

__all__ = [
    "PolicyBindApplication",
    "create_app",
    "run_server",
]
