from datetime import datetime
from flask import request, jsonify

def error_response(status, code, message, details=None):
    return jsonify({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "path": request.path,
        "status": status,
        "code": code,
        "message": message,
        "details": details or {}
    }), status