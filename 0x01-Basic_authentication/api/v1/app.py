#!/usr/bin/env python3
"""
Main module for the API
"""
from os import getenv
from flask import Flask, jsonify, abort, request
from flask_cors import CORS
from api.v1.views import app_views
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.auth import Auth

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth_type = getenv('AUTH_TYPE', 'auth')
auth = None

# Set up authentication based on environment variable
if auth_type == 'basic_auth':
    auth = BasicAuth()
else:
    auth = Auth()

@app.before_request
def before_request() -> str:
    """Handle authentication before processing a request"""
    if auth is None:
        return

    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/'
    ]
    if auth.require_auth(request.path, excluded_paths):
        auth_header = auth.authorization_header(request)
        user = auth.current_user(request)
        if auth_header is None:
            abort(401)
        if user is None:
            abort(403)

@app.errorhandler(404)
def not_found(error) -> str:
    """Handle 404 Not Found errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(error) -> str:
    """Handle 401 Unauthorized errors"""
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(error) -> str:
    """Handle 403 Forbidden errors"""
    return jsonify({"error": "Forbidden"}), 403

if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)

