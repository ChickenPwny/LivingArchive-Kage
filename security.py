"""
Security Hardening Module for Kage Flask App
============================================
Implements security measures to protect against drive-by attacks:
- CSRF protection
- Security headers
- Input validation
- Rate limiting
- CORS restrictions
"""
import re
import uuid
from functools import wraps
from flask import request, jsonify, g
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize CSRF protection
csrf = CSRFProtect()

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

def init_security(app):
    """Initialize security features for Flask app"""
    # Initialize CSRF protection
    csrf.init_app(app)
    
    # Initialize rate limiter
    limiter.init_app(app)
    
    # Add security headers
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline scripts for templates
            "style-src 'self' 'unsafe-inline'; "  # Allow inline styles
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self' http://localhost:* ws://localhost:*; "  # Allow localhost API calls
            "frame-ancestors 'none'; "  # Prevent framing
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # XSS Protection (legacy, but still useful)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=()'
        )
        
        return response

def validate_uuid(value):
    """Validate that a value is a valid UUID"""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False

def validate_domain(domain):
    """Validate domain name format"""
    if not domain or len(domain) > 255:
        return False
    # Basic domain validation regex
    pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain.lower()))

def validate_ip_address(ip):
    """Validate IP address format (IPv4 or IPv6)"""
    if not ip:
        return False
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return bool(re.match(ipv6_pattern, ip))

def sanitize_string(value, max_length=255):
    """Sanitize string input"""
    if not value:
        return None
    if not isinstance(value, str):
        value = str(value)
    # Remove null bytes and control characters
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    # Trim whitespace
    value = value.strip()
    # Limit length
    if len(value) > max_length:
        value = value[:max_length]
    return value

def validate_json_input(required_fields=None, optional_fields=None):
    """Decorator to validate JSON input"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Content-Type must be application/json'
                }), 400
            
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Invalid JSON payload'
                }), 400
            
            # Validate required fields
            if required_fields:
                for field in required_fields:
                    if field not in data:
                        return jsonify({
                            'success': False,
                            'error': f'Missing required field: {field}'
                        }), 400
            
            # Store validated data in g for use in route
            g.validated_data = data
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_csrf(f):
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # CSRF is automatically handled by Flask-WTF
        # This decorator is mainly for documentation
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorators for specific endpoints
def api_rate_limit():
    """Rate limit for API endpoints"""
    return limiter.limit("30 per minute")

def daemon_api_rate_limit():
    """Rate limit for daemon API endpoints (more permissive)"""
    return limiter.limit("100 per minute")

def agentic_api_rate_limit():
    """Rate limit for agentic AI endpoints (more restrictive)"""
    return limiter.limit("10 per minute")

