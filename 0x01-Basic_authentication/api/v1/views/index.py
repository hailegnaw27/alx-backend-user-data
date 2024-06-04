#!/usr/bin/env python3
"""View definitions for the API endpoints.
"""
from flask import jsonify, abort
from api.v1.views import app_views

@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """
    GET /api/v1/status
    Returns:
      - A JSON response indicating the status of the API.
    """
    return jsonify({"status": "OK"})

@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """
    GET /api/v1/stats
    Returns:
      - A JSON response with the count of each type of object.
    """
    from models.user import User
    stats = {
        'users': User.count()
    }
    return jsonify(stats)

@app_views.route('/unauthorized/', strict_slashes=False)
def unauthorized() -> None:
    """
    GET /api/v1/unauthorized
    Returns:
      - A 401 Unauthorized error.
    """
    abort(401)

@app_views.route('/forbidden/', strict_slashes=False)
def forbidden() -> None:
    """
    GET /api/v1/forbidden
    Returns:
      - A 403 Forbidden error.
    """
    abort(403)

