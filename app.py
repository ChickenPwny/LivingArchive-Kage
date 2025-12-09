"""
Flask Application for Kage Port Scanner
========================================
Flask-based web interface for Kage port scanning daemon.
Uses SQLite for data storage.
"""
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_cors import CORS
import sqlite3
import os
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
import uuid

# Security imports
from security import (
    init_security, csrf, limiter,
    validate_uuid, validate_domain, validate_ip_address, sanitize_string,
    validate_json_input, api_rate_limit, daemon_api_rate_limit, agentic_api_rate_limit
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'kage-flask-secret-key-change-in-production')
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'kage.db')
app.config['JSON_AS_ASCII'] = False

# CSRF Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = False  # Set to True in production with HTTPS

# CORS Configuration - Restrict to specific origins
allowed_origins = os.environ.get('CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')
CORS(app, origins=allowed_origins, supports_credentials=True)

# Initialize security features
init_security(app)

# Initialize agentic AI extension (LivingArchive-clean integration)
try:
    from agentic_kage import get_agentic_kage
    agentic_kage = get_agentic_kage(
        llm_gateway_url=os.environ.get('LLM_GATEWAY_URL', 'http://localhost:8082'),
        api_key=os.environ.get('EGOLLAMA_API_KEY')
    )
    logger.info(f"🤖 Agentic AI extension initialized (LivingArchive-clean: {agentic_kage.enabled})")
except Exception as e:
    logger.warning(f"⚠️ Agentic AI extension not available: {e}")
    agentic_kage = None

# Database helper functions
def get_db():
    """Get database connection"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database schema"""
    db = get_db()
    cursor = db.cursor()
    
    # Create eggrecords table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS eggrecords (
            id TEXT PRIMARY KEY,
            subdomain TEXT,
            domainname TEXT,
            ip_address TEXT,
            cidr TEXT,
            eggname TEXT,
            projectegg TEXT,
            alive INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create nmap_scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nmap_scans (
            id TEXT PRIMARY KEY,
            record_id TEXT,
            target TEXT,
            scan_type TEXT DEFAULT 'kage_port_scan',
            scan_status TEXT DEFAULT 'completed',
            port TEXT,
            service_name TEXT,
            service_version TEXT,
            open_ports TEXT,
            scan_command TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (record_id) REFERENCES eggrecords(id)
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_eggrecords_alive ON eggrecords(alive)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_eggrecords_updated ON eggrecords(updated_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_nmap_record_id ON nmap_scans(record_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_nmap_scan_type ON nmap_scans(scan_type)')
    
    db.commit()
    db.close()
    logger.info("Database initialized")

# Initialize database on startup
if not os.path.exists(app.config['DATABASE']):
    init_db()

# Routes
@app.route('/')
def index():
    """Home page - Kage main dashboard"""
    db = get_db()
    cursor = db.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) as total FROM eggrecords')
    total_eggrecords = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as alive FROM eggrecords WHERE alive = 1')
    alive_eggrecords = cursor.fetchone()['alive']
    
    cursor.execute('SELECT COUNT(*) as scans FROM nmap_scans')
    total_scans = cursor.fetchone()['scans']
    
    # Get recent scans (last 24 hours)
    one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
    cursor.execute("SELECT COUNT(*) FROM nmap_scans WHERE created_at > ?", (one_day_ago,))
    recent_scans_24h = cursor.fetchone()[0]
    
    db.close()
    
    is_empty = total_eggrecords == 0
    
    context = {
        'title': 'Kage Port Scanner',
        'icon': '🔍',
        'total_eggrecords': total_eggrecords,
        'alive_eggrecords': alive_eggrecords,
        'total_scans': total_scans,
        'recent_scans_24h': recent_scans_24h,
        'is_empty': is_empty
    }
    
    return render_template('index.html', **context)

@app.route('/general/')
def general_dashboard():
    """General dashboard"""
    db = get_db()
    cursor = db.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) as total FROM eggrecords')
    total = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as alive FROM eggrecords WHERE alive = 1')
    alive = cursor.fetchone()['alive']
    
    cursor.execute('SELECT COUNT(*) as scans FROM nmap_scans')
    scans = cursor.fetchone()['scans']
    
    # Get recent eggrecords
    cursor.execute('''
        SELECT e.*, 
               (SELECT COUNT(*) FROM nmap_scans WHERE record_id = e.id) as scan_count
        FROM eggrecords e
        ORDER BY e.updated_at DESC
        LIMIT 50
    ''')
    eggrecords = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    return render_template('reconnaissance/general_dashboard.html',
                         total=total,
                         alive=alive,
                         scans=scans,
                         eggrecords=eggrecords)

@app.route('/kage/')
def kage_dashboard():
    """Kage dashboard"""
    db = get_db()
    cursor = db.cursor()
    
    # Get Kage scan statistics
    cursor.execute('''
        SELECT COUNT(*) as total_scans
        FROM nmap_scans
        WHERE scan_type = 'kage_port_scan'
    ''')
    total_scans = cursor.fetchone()['total_scans']
    
    # Get recent scans
    cursor.execute('''
        SELECT n.*, e.subdomain, e.domainname
        FROM nmap_scans n
        LEFT JOIN eggrecords e ON n.record_id = e.id
        WHERE n.scan_type = 'kage_port_scan'
        ORDER BY n.created_at DESC
        LIMIT 50
    ''')
    scans = [dict(row) for row in cursor.fetchall()]
    
    # Check daemon status
    pid_file = Path('/tmp/kage_daemon.pid')
    daemon_status = 'stopped'
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            daemon_status = 'running'
        except (ProcessLookupError, ValueError, OSError):
            daemon_status = 'stopped'
    
    db.close()
    
    return render_template('reconnaissance/kage_dashboard.html',
                         total_scans=total_scans,
                         scans=scans,
                         daemon_status=daemon_status)

@app.route('/eggrecords/')
def eggrecord_list():
    """List all eggrecords"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT e.*,
               (SELECT COUNT(*) FROM nmap_scans WHERE record_id = e.id) as scan_count
        FROM eggrecords e
        ORDER BY e.updated_at DESC
        LIMIT 200
    ''')
    eggrecords = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('SELECT COUNT(*) as total FROM eggrecords')
    total = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as alive FROM eggrecords WHERE alive = 1')
    alive = cursor.fetchone()['alive']
    
    db.close()
    
    return render_template('reconnaissance/eggrecord_list.html',
                         eggrecords=eggrecords,
                         total=total,
                         alive=alive)

@app.route('/eggrecords/<eggrecord_id>/')
def eggrecord_detail(eggrecord_id):
    """EggRecord detail page"""
    # Validate eggrecord_id to prevent path traversal
    if not validate_uuid(eggrecord_id):
        return "Invalid eggrecord ID format", 400
    
    db = get_db()
    cursor = db.cursor()
    
    # Get eggrecord
    cursor.execute('SELECT * FROM eggrecords WHERE id = ?', (eggrecord_id,))
    eggrecord = cursor.fetchone()
    
    if not eggrecord:
        return "EggRecord not found", 404
    
    eggrecord = dict(eggrecord)
    
    # Get related scans
    cursor.execute('''
        SELECT * FROM nmap_scans
        WHERE record_id = ?
        ORDER BY created_at DESC
    ''', (eggrecord_id,))
    scans = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    return render_template('reconnaissance/eggrecord_detail.html',
                         eggrecord=eggrecord,
                         scans=scans)

# API Endpoints
@app.route('/api/kage/status/')
@api_rate_limit()
def kage_status_api():
    """API: Get Kage service status"""
    try:
        # Check daemon status
        pid_file = Path('/tmp/kage_daemon.pid')
        status = 'stopped'
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)
                status = 'running'
            except (ProcessLookupError, ValueError, OSError):
                status = 'stopped'
        
        # Get database stats
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            SELECT COUNT(*) as total_scans
            FROM nmap_scans
            WHERE scan_type = 'kage_port_scan'
        ''')
        total_scans = cursor.fetchone()['total_scans']
        db.close()
        
        return jsonify({
            'success': True,
            'status': status,
            'message': f'Kage is {status}',
            'total_scans': total_scans
        })
    except Exception as e:
        logger.error(f"Error checking Kage status: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'status': 'unknown',
            'error': str(e)
        }), 500

@app.route('/api/kage/<action>/', methods=['POST'])
@csrf.exempt  # Exempt from CSRF for daemon control (can be re-enabled with proper token handling)
@api_rate_limit()
def kage_control_api(action):
    """API: Control Kage daemon"""
    # Validate action parameter
    action = sanitize_string(action, max_length=20)
    if action not in ['start', 'pause', 'kill']:
        return jsonify({
            'success': False,
            'error': f'Invalid action: {action}. Must be start, pause, or kill'
        }), 400
    
    return jsonify({
        'success': True,
        'status': 'stopped',
        'message': f'{action.capitalize()} command received for Kage. Note: Daemons must be started manually.',
        'note': 'This is a simplified implementation. Full daemon control requires the daemon processes to be running.'
    })

@app.route('/api/eggrecords/create/', methods=['POST'])
@api_rate_limit()
@validate_json_input(required_fields=['domainname'])
def create_eggrecord_api():
    """API: Create new eggrecord"""
    try:
        data = g.validated_data
        
        # Validate and sanitize input
        domainname = sanitize_string(data.get('domainname'), max_length=255)
        if not domainname or not validate_domain(domainname):
            return jsonify({
                'success': False,
                'error': 'Invalid domainname format'
            }), 400
        
        subdomain = sanitize_string(data.get('subdomain'), max_length=255)
        ip_address = sanitize_string(data.get('ip_address'), max_length=45)
        if ip_address and not validate_ip_address(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400
        
        cidr = sanitize_string(data.get('cidr'), max_length=50)
        eggname = sanitize_string(data.get('eggname'), max_length=255)
        projectegg = sanitize_string(data.get('projectegg'), max_length=255)
        alive = bool(data.get('alive', True))
        
        eggrecord_id = str(uuid.uuid4())
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO eggrecords (id, subdomain, domainname, ip_address, cidr, eggname, projectegg, alive)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            eggrecord_id,
            subdomain,
            domainname,
            ip_address,
            cidr,
            eggname,
            projectegg,
            alive
        ))
        db.commit()
        db.close()
        
        return jsonify({
            'success': True,
            'id': eggrecord_id,
            'message': 'EggRecord created successfully'
        })
    except Exception as e:
        logger.error(f"Error creating eggrecord: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Daemon API endpoints (for Kage daemon to use)
@app.route('/reconnaissance/api/daemon/kage/eggrecords/')
@csrf.exempt  # Exempt daemon endpoints from CSRF (internal use)
@daemon_api_rate_limit()
def daemon_get_eggrecords():
    """API: Get eggrecords for Kage daemon to process"""
    try:
        # Validate and limit the limit parameter
        limit_str = request.args.get('limit', '10')
        try:
            limit = int(limit_str)
            if limit < 1 or limit > 100:  # Enforce reasonable limits
                limit = 10
        except ValueError:
            limit = 10
        
        db = get_db()
        cursor = db.cursor()
        
        # Get eggrecords that need scanning
        cursor.execute('''
            SELECT DISTINCT e.id, e.subdomain, e.domainname, e.alive, e.updated_at
            FROM eggrecords e
            LEFT JOIN nmap_scans n ON n.record_id = e.id 
                AND n.scan_type = 'kage_port_scan'
            WHERE e.alive = 1
            AND (n.id IS NULL OR datetime(n.created_at) < datetime('now', '-24 hours'))
            ORDER BY e.updated_at ASC
            LIMIT ?
        ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row['id'],
                'subDomain': row['subdomain'],
                'domainname': row['domainname'],
                'alive': bool(row['alive']),
                'updated_at': row['updated_at']
            })
        
        db.close()
        
        return jsonify({
            'success': True,
            'count': len(results),
            'eggrecords': results
        })
    except Exception as e:
        logger.error(f"Error getting eggrecords: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/reconnaissance/api/daemon/kage/scan/', methods=['POST'])
@csrf.exempt  # Exempt daemon endpoints from CSRF (internal use)
@daemon_api_rate_limit()
@validate_json_input(required_fields=['eggrecord_id', 'target', 'result'])
def daemon_submit_scan():
    """API: Submit Nmap scan results from Kage daemon"""
    try:
        data = g.validated_data
        
        # Validate eggrecord_id
        eggrecord_id = data.get('eggrecord_id')
        if not eggrecord_id or not validate_uuid(eggrecord_id):
            return jsonify({'success': False, 'error': 'Invalid eggrecord_id format'}), 400
        
        # Sanitize and validate other fields
        target = sanitize_string(data.get('target', 'unknown'), max_length=255)
        scan_type = sanitize_string(data.get('scan_type', 'kage_port_scan'), max_length=50)
        if scan_type not in ['kage_port_scan', 'jade_port_scan']:  # Whitelist allowed scan types
            scan_type = 'kage_port_scan'
        
        result = data.get('result', {})
        if not isinstance(result, dict):
            return jsonify({'success': False, 'error': 'result must be a dictionary'}), 400
        
        open_ports = result.get('open_ports', [])
        if not open_ports:
            return jsonify({'success': False, 'error': 'No open ports in result'}), 400
        
        scan_id = str(uuid.uuid4())
        
        # Prepare open_ports JSON
        ports_json = json.dumps([
            {
                'port': p.get('port') if isinstance(p, dict) else p,
                'protocol': p.get('protocol', 'tcp') if isinstance(p, dict) else 'tcp',
                'service': p.get('service_name', '') if isinstance(p, dict) else '',
                'version': p.get('service_version', '') if isinstance(p, dict) else '',
                'state': 'open',
                'banner': p.get('service_info', '') if isinstance(p, dict) else ''
            }
            for p in open_ports
        ])
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO nmap_scans 
                (id, record_id, target, scan_type, scan_status, port, service_name, 
                 service_version, open_ports, scan_command, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            eggrecord_id,
            target,
            scan_type,
            'completed',
            str(open_ports[0].get('port', '')) if open_ports else '',
            open_ports[0].get('service_name', '') if open_ports else '',
            open_ports[0].get('service_version', '') if open_ports else '',
            ports_json,
            result.get('scan_command', f'nmap scan for {target}'),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        db.commit()
        db.close()
        
        return jsonify({
            'success': True,
            'message': f'Scan result submitted for {target}'
        })
    except Exception as e:
        logger.error(f"Error submitting scan: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/reconnaissance/api/daemon/kage/health/')
@csrf.exempt  # Exempt health check from CSRF
@daemon_api_rate_limit()
def daemon_health_check():
    """API: Health check endpoint for Kage daemon"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT 1')
        db_healthy = True
        db.close()
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        db_healthy = False
    
    health_status = 'healthy' if db_healthy else 'degraded'
    
    # Check agentic AI status
    ai_available = agentic_kage.is_available() if agentic_kage else False
    
    return jsonify({
        'success': True,
        'status': health_status,
        'personality': 'kage',
        'database': 'connected' if db_healthy else 'disconnected',
        'functional': db_healthy,
        'agentic_ai': 'available' if ai_available else 'unavailable',
        'llm_gateway': agentic_kage.llm_gateway_url if agentic_kage else None,
        'timestamp': datetime.now().isoformat()
    })

# Agentic AI Endpoints (LivingArchive-clean extension)
@app.route('/api/kage/agentic/prioritize/', methods=['POST'])
@agentic_api_rate_limit()
@validate_json_input(required_fields=['targets'])
def ai_prioritize_targets_api():
    """API: Use AI to prioritize targets for scanning"""
    if not agentic_kage or not agentic_kage.is_available():
        return jsonify({
            'success': False,
            'error': 'Agentic AI not available. Start LivingArchive-clean gateway.',
            'fallback': 'Using default priority order'
        }), 503
    
    try:
        data = g.validated_data
        targets = data.get('targets', [])
        if not isinstance(targets, list) or len(targets) > 100:  # Limit batch size
            return jsonify({
                'success': False,
                'error': 'targets must be a list with max 100 items'
            }), 400
        
        context = data.get('context', {})
        if not isinstance(context, dict):
            context = {}
        
        prioritized = agentic_kage.prioritize_targets(targets, context)
        
        return jsonify({
            'success': True,
            'prioritized': [
                {
                    'target': p.target,
                    'priority_score': p.priority_score,
                    'reasoning': p.reasoning,
                    'recommended_strategy': p.recommended_strategy
                }
                for p in prioritized
            ]
        })
    except Exception as e:
        logger.error(f"Error in AI prioritization: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/kage/agentic/strategy/', methods=['POST'])
@agentic_api_rate_limit()
@validate_json_input(required_fields=['target'])
def ai_generate_strategy_api():
    """API: Use AI to generate scan strategy for a target"""
    if not agentic_kage or not agentic_kage.is_available():
        return jsonify({
            'success': False,
            'error': 'Agentic AI not available',
            'fallback': {'ports': [80, 443, 8080], 'technique': 'tcp_syn'}
        }), 503
    
    try:
        data = g.validated_data
        target = sanitize_string(data.get('target'), max_length=255)
        if not target:
            return jsonify({'success': False, 'error': 'target required'}), 400
        
        target_info = data.get('target_info', {})
        if not isinstance(target_info, dict):
            target_info = {}
        
        previous_scans = data.get('previous_scans', [])
        if not isinstance(previous_scans, list):
            previous_scans = []
        
        strategy = agentic_kage.generate_scan_strategy(target, target_info, previous_scans)
        
        return jsonify({
            'success': True,
            'strategy': strategy
        })
    except Exception as e:
        logger.error(f"Error generating AI strategy: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/kage/agentic/analyze/', methods=['POST'])
@agentic_api_rate_limit()
@validate_json_input(required_fields=['target', 'scan_results'])
def ai_analyze_results_api():
    """API: Use AI to analyze scan results"""
    if not agentic_kage or not agentic_kage.is_available():
        return jsonify({
            'success': False,
            'error': 'Agentic AI not available',
            'fallback': {'summary': 'AI analysis unavailable'}
        }), 503
    
    try:
        data = g.validated_data
        target = sanitize_string(data.get('target'), max_length=255)
        if not target:
            return jsonify({'success': False, 'error': 'target required'}), 400
        
        scan_results = data.get('scan_results', {})
        if not isinstance(scan_results, dict):
            return jsonify({'success': False, 'error': 'scan_results must be a dictionary'}), 400
        
        analysis = agentic_kage.analyze_scan_results(target, scan_results)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
    except Exception as e:
        logger.error(f"Error in AI analysis: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/kage/agentic/decide/', methods=['POST'])
@agentic_api_rate_limit()
@validate_json_input(required_fields=['target'])
def ai_decide_action_api():
    """API: Use AI to decide next action based on scan results"""
    if not agentic_kage or not agentic_kage.is_available():
        return jsonify({
            'success': False,
            'error': 'Agentic AI not available',
            'fallback': {'action': 'move_next', 'reasoning': 'AI unavailable'}
        }), 503
    
    try:
        data = g.validated_data
        target = sanitize_string(data.get('target'), max_length=255)
        if not target:
            return jsonify({'success': False, 'error': 'target required'}), 400
        
        scan_results = data.get('scan_results', {})
        if not isinstance(scan_results, dict):
            scan_results = {}
        
        analysis = data.get('analysis')
        if not isinstance(analysis, dict):
            analysis = None
        
        decision = agentic_kage.decide_next_action(target, scan_results, analysis)
        
        return jsonify({
            'success': True,
            'decision': {
                'action': decision.action,
                'reasoning': decision.reasoning,
                'confidence': decision.confidence,
                'parameters': decision.parameters,
                'next_steps': decision.next_steps
            }
        })
    except Exception as e:
        logger.error(f"Error in AI decision: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/kage/agentic/status/')
@api_rate_limit()
def agentic_ai_status():
    """API: Get agentic AI extension status"""
    if not agentic_kage:
        return jsonify({
            'success': False,
            'available': False,
            'error': 'Agentic AI extension not initialized'
        })
    
    return jsonify({
        'success': True,
        'available': agentic_kage.is_available(),
        'llm_gateway_url': agentic_kage.llm_gateway_url,
        'enabled': agentic_kage.enabled,
        'message': 'Agentic AI available' if agentic_kage.is_available() else 'Start LivingArchive-clean gateway to enable'
    })

if __name__ == '__main__':
    # Initialize database if needed
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    
    # Run Flask app
    # IMPORTANT: Set debug=False in production!
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)

