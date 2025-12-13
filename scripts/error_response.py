from datetime import datetime, UTC
from flask import request, jsonify

def error_response(status, code, message, details=None):
    return jsonify({
        "timestamp": datetime.now(UTC).isoformat() + "Z",
        "path": request.path,
        "status": status,
        "code": code,
        "message": message,
        "details": details or {}
    }), status