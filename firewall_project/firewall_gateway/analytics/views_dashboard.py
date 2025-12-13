"""
Integrated Dashboard Views - Collatz Visualization and User Insights
"""

from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
import json
from datetime import datetime, timedelta

# analytics_engine will be imported at function call time to avoid circular imports
analytics_engine = None

def get_analytics_engine():
    """Get the global analytics engine instance (lazy import to avoid circular imports)"""
    global analytics_engine
    if analytics_engine is None:
        from .views import analytics_engine as ae
        analytics_engine = ae
    return analytics_engine


def dashboard_main(request):
    """Unified Admin Panel and Dashboard - All-in-one interface"""
    from .views import analytics_engine as ae

    admin_token = request.COOKIES.get('admin_token')

    if not admin_token or not ae.verify_admin_session(admin_token):
        return redirect_to_login()

    # Get all data
    pending_devices = ae.get_pending_devices()
    whitelist = ae.get_whitelist()
    stats = ae.get_performance_summary()
    active_sessions = ae.get_active_sessions()

    # Build comprehensive unified HTML with tabs
    html = get_unified_admin_html(pending_devices, whitelist, stats, active_sessions, ae)
    return HttpResponse(html)


def collatz_graphs(request):
    """Collatz sequence visualization page with Chart.js"""
    admin_token = request.COOKIES.get('admin_token')

    if not admin_token or not analytics_engine.verify_admin_session(admin_token):
        return redirect_to_login()

    whitelist = analytics_engine.get_whitelist()
    devices_data = []

    # Collect Collatz data for all approved devices
    for ip in whitelist['whitelisted_ips']:
        seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
        if seq_info.get('found'):
            device_info = analytics_engine.device_registry.get(ip, {})
            devices_data.append({
                'ip': ip,
                'device_type': device_info.get('device_type', 'Unknown'),
                'sequence': seq_info['sequence'],
                'hash': seq_info['hash']
            })

    html = get_collatz_graph_html(devices_data)
    return HttpResponse(html)


def user_insights(request):
    """User session analytics page"""
    admin_token = request.COOKIES.get('admin_token')

    if not admin_token or not analytics_engine.verify_admin_session(admin_token):
        return redirect_to_login()

    active_sessions = analytics_engine.get_active_sessions()
    device_registry = analytics_engine.device_registry

    # Build insights data
    insights_data = []
    for ip, session_info in active_sessions['active_sessions'].items():
        device_info = device_registry.get(ip, {})

        # Calculate duration
        first_access = datetime.fromisoformat(session_info['first_access'])
        last_access = datetime.fromisoformat(session_info['last_access'])
        duration = (last_access - first_access).total_seconds()
        duration_hours = duration / 3600

        insights_data.append({
            'ip': ip,
            'device_type': device_info.get('device_type', 'Unknown'),
            'first_access': session_info['first_access'][:19],
            'last_access': session_info['last_access'][:19],
            'duration_seconds': int(duration),
            'duration_hours': round(duration_hours, 2),
            'access_count': session_info['access_count']
        })

    html = get_user_insights_html(insights_data)
    return HttpResponse(html)


@require_http_methods(["GET"])
def api_collatz_graphs(request):
    """API endpoint for Collatz graph data"""
    try:
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

        whitelist = analytics_engine.get_whitelist()
        devices_data = []

        for ip in whitelist['whitelisted_ips']:
            seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
            if seq_info.get('found'):
                device_info = analytics_engine.device_registry.get(ip, {})
                devices_data.append({
                    'ip': ip,
                    'device_type': device_info.get('device_type', 'Unknown'),
                    'sequence': seq_info['sequence'],
                    'sequence_length': len(seq_info['sequence']),
                    'max_value': max(seq_info['sequence']) if seq_info['sequence'] else 0,
                    'hash': seq_info['hash']
                })

        return JsonResponse({
            'success': True,
            'devices': devices_data,
            'count': len(devices_data)
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["GET"])
def api_user_insights(request):
    """API endpoint for user insights data"""
    try:
        admin_token = request.COOKIES.get('admin_token')
        if not admin_token or not analytics_engine.verify_admin_session(admin_token):
            return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

        active_sessions = analytics_engine.get_active_sessions()
        device_registry = analytics_engine.device_registry

        insights_data = []
        for ip, session_info in active_sessions['active_sessions'].items():
            device_info = device_registry.get(ip, {})
            first_access = datetime.fromisoformat(session_info['first_access'])
            last_access = datetime.fromisoformat(session_info['last_access'])
            duration = (last_access - first_access).total_seconds()

            insights_data.append({
                'ip': ip,
                'device_type': device_info.get('device_type', 'Unknown'),
                'first_access': session_info['first_access'],
                'last_access': session_info['last_access'],
                'duration_seconds': int(duration),
                'access_count': session_info['access_count']
            })

        return JsonResponse({
            'success': True,
            'insights': insights_data,
            'count': len(insights_data)
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


def redirect_to_login():
    """Redirect to login page"""
    from django.http import HttpResponseRedirect
    return HttpResponseRedirect('/analytics/admin/login/')


def get_unified_admin_html(pending_devices, whitelist, stats, active_sessions, analytics_engine):
    """Generate unified admin panel with tabbed interface for all functionality"""

    # Build pending devices section
    pending_html = ""
    if pending_devices:
        for ip, info in pending_devices.items():
            pending_html += f"""
            <div class="device-card pending">
                <div class="device-header">
                    <span class="device-type-badge">{info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge pending">PENDING</span>
                </div>
                <div class="device-details">
                    <p><strong>Requested:</strong> {info.get('timestamp', 'N/A')}</p>
                    <p><strong>User Agent:</strong> <small>{info.get('user_agent', 'Unknown')[:70]}</small></p>
                </div>
                <div class="device-actions">
                    <button class="btn-approve" onclick="approveDevice('{ip}')">✓ Approve</button>
                    <button class="btn-reject" onclick="rejectDevice('{ip}')">✗ Reject</button>
                </div>
            </div>
            """
    else:
        pending_html = '<div class="no-data">No pending devices</div>'

    # Build approved/whitelisted devices section
    whitelisted_html = ""
    if whitelist['whitelisted_ips']:
        for ip in whitelist['whitelisted_ips']:
            device_info = analytics_engine.device_registry.get(ip, {})
            whitelist_entry = whitelist['whitelist_data'].get(ip, {})
            hash_value = whitelist_entry.get('hash', 'N/A')
            timestamp = whitelist_entry.get('timestamp', 'N/A')

            seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
            sequence = seq_info.get('sequence', []) if seq_info.get('found') else []
            seq_length = len(sequence)

            whitelisted_html += f"""
            <div class="device-card whitelisted">
                <div class="device-header">
                    <span class="device-type-badge">{device_info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge approved">✓ APPROVED</span>
                </div>
                <div class="device-details">
                    <p><strong>Approved:</strong> {timestamp}</p>
                    <p><strong>SHA1-E3 Hash:</strong> <code>{hash_value}</code></p>
                    <p><strong>Collatz Sequence Length:</strong> {seq_length} steps</p>
                </div>
                <div class="device-actions">
                    <button class="btn-remove" onclick="removeWhitelist('{ip}')">Remove</button>
                </div>
            </div>
            """
    else:
        whitelisted_html = '<div class="no-data">No approved devices</div>'

    # Build active sessions section
    sessions_html = ""
    if active_sessions['active_sessions']:
        for ip, session_info in active_sessions['active_sessions'].items():
            device_info = analytics_engine.device_registry.get(ip, {})
            first_access = session_info.get('first_access', 'N/A')[:19]
            last_access = session_info.get('last_access', 'N/A')[:19]
            access_count = session_info.get('access_count', 0)

            sessions_html += f"""
            <div class="session-card">
                <div class="device-header">
                    <span class="device-type-badge">{session_info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge active">● ACTIVE</span>
                </div>
                <div class="session-details">
                    <p><strong>Requests:</strong> {access_count}</p>
                    <p><strong>First Access:</strong> {first_access}</p>
                    <p><strong>Last Access:</strong> {last_access}</p>
                </div>
            </div>
            """
    else:
        sessions_html = '<div class="no-data">No active sessions</div>'

    # Build Collatz visualization data
    collatz_charts = ""
    if whitelist['whitelisted_ips']:
        for ip in whitelist['whitelisted_ips']:
            seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
            if seq_info.get('found'):
                sequence = seq_info['sequence']
                hash_val = seq_info['hash']
                device_type = analytics_engine.device_registry.get(ip, {}).get('device_type', 'Unknown')

                # Create a chart container
                chart_id = f"chart_{ip.replace('.', '_')}"
                collatz_charts += f"""
                <div class="collatz-chart-container">
                    <h4>{device_type} ({ip}) - Hash: {hash_val}</h4>
                    <canvas id="{chart_id}" style="max-height: 300px;"></canvas>
                </div>
                <script>
                    new Chart(document.getElementById('{chart_id}'), {{
                        type: 'line',
                        data: {{
                            labels: Array.from({{length: {len(sequence)}}}, (_, i) => i),
                            datasets: [{{
                                label: 'Collatz Sequence',
                                data: {json.dumps(sequence)},
                                borderColor: '#0078d4',
                                backgroundColor: 'rgba(0, 120, 212, 0.1)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.1
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{ legend: {{ display: true }} }}
                        }}
                    }});
                </script>
                """

    # Stats summary
    stats_html = f"""
    <div class="stats-row">
        <div class="stat-card">
            <div class="stat-number">{len(whitelist['whitelisted_ips'])}</div>
            <div class="stat-label">Approved Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(pending_devices)}</div>
            <div class="stat-label">Pending Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(active_sessions.get('active_sessions', {}))}</div>
            <div class="stat-label">Active Sessions</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{stats.get('total_verifications', 0)}</div>
            <div class="stat-label">Total Verifications</div>
        </div>
    </div>
    """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Panel - Firewall Gateway</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 16px;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }}
            header {{
                background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
                color: white;
                padding: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            header h1 {{
                font-size: 28px;
                font-weight: 600;
            }}
            .logout-btn {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.5);
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.3s;
            }}
            .logout-btn:hover {{
                background: rgba(255, 255, 255, 0.3);
            }}
            .tabs {{
                display: flex;
                background: #f0f0f0;
                border-bottom: 2px solid #e0e0e0;
                gap: 0;
            }}
            .tab-button {{
                padding: 16px 24px;
                border: none;
                background: none;
                cursor: pointer;
                font-size: 14px;
                font-weight: 500;
                color: #333;
                transition: all 0.3s;
                border-bottom: 3px solid transparent;
            }}
            .tab-button:hover {{
                background: rgba(0, 120, 212, 0.05);
            }}
            .tab-button.active {{
                color: #0078d4;
                border-bottom-color: #0078d4;
                background: white;
            }}
            .tab-content {{
                padding: 30px;
                display: none;
            }}
            .tab-content.active {{
                display: block;
            }}
            .stats-row {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: rgba(255, 255, 255, 0.8);
                border: 1px solid rgba(0, 120, 212, 0.2);
                border-radius: 12px;
                padding: 20px;
                text-align: center;
                transition: all 0.3s;
            }}
            .stat-card:hover {{
                transform: translateY(-4px);
                border-color: #0078d4;
                box-shadow: 0 4px 12px rgba(0, 120, 212, 0.15);
            }}
            .stat-number {{
                font-size: 32px;
                font-weight: bold;
                color: #0078d4;
                margin-bottom: 8px;
            }}
            .stat-label {{
                font-size: 13px;
                color: #666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .devices-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                gap: 20px;
            }}
            .device-card {{
                background: rgba(255, 255, 255, 0.85);
                border: 1px solid #ddd;
                border-radius: 12px;
                padding: 16px;
                transition: all 0.3s;
            }}
            .device-card.pending {{
                border-left: 4px solid #ff9800;
            }}
            .device-card.whitelisted {{
                border-left: 4px solid #4caf50;
            }}
            .device-card:hover {{
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                transform: translateY(-2px);
            }}
            .device-header {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 12px;
                flex-wrap: wrap;
            }}
            .device-type-badge {{
                background: #e3f2fd;
                color: #0078d4;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .device-ip {{
                font-family: 'Courier New', monospace;
                font-weight: 600;
                color: #333;
            }}
            .status-badge {{
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .status-badge.pending {{
                background: #fff3e0;
                color: #e65100;
            }}
            .status-badge.approved {{
                background: #e8f5e9;
                color: #2e7d32;
            }}
            .status-badge.active {{
                background: #f3e5f5;
                color: #6a1b9a;
            }}
            .device-details {{
                font-size: 13px;
                color: #555;
                margin-bottom: 12px;
            }}
            .device-details p {{
                margin: 6px 0;
            }}
            .device-details code {{
                background: #f5f5f5;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                color: #d32f2f;
            }}
            .device-actions {{
                display: flex;
                gap: 8px;
            }}
            .device-actions button {{
                flex: 1;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 600;
                transition: all 0.3s;
            }}
            .btn-approve {{
                background: #4caf50;
                color: white;
                border-color: #4caf50;
            }}
            .btn-approve:hover {{
                background: #388e3c;
                transform: scale(1.02);
            }}
            .btn-reject {{
                background: #f44336;
                color: white;
                border-color: #f44336;
            }}
            .btn-reject:hover {{
                background: #d32f2f;
                transform: scale(1.02);
            }}
            .btn-remove {{
                background: #ff9800;
                color: white;
                border-color: #ff9800;
            }}
            .btn-remove:hover {{
                background: #e65100;
                transform: scale(1.02);
            }}
            .session-card {{
                background: rgba(255, 255, 255, 0.85);
                border: 1px solid #ddd;
                border-left: 4px solid #9c27b0;
                border-radius: 12px;
                padding: 16px;
                margin-bottom: 16px;
                transition: all 0.3s;
            }}
            .session-card:hover {{
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                transform: translateY(-2px);
            }}
            .session-details {{
                font-size: 13px;
                color: #555;
            }}
            .session-details p {{
                margin: 6px 0;
            }}
            .collatz-chart-container {{
                background: rgba(255, 255, 255, 0.85);
                border: 1px solid #ddd;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 20px;
            }}
            .collatz-chart-container h4 {{
                margin-bottom: 15px;
                color: #333;
                font-size: 14px;
            }}
            .collatz-chart-container canvas {{
                max-height: 400px;
            }}
            .no-data {{
                text-align: center;
                color: #999;
                padding: 40px 20px;
                font-size: 14px;
            }}
            @media (max-width: 768px) {{
                header {{
                    flex-direction: column;
                    gap: 15px;
                }}
                .tabs {{
                    flex-wrap: wrap;
                }}
                .tab-button {{
                    flex: 1;
                    min-width: 100px;
                }}
                .devices-grid {{
                    grid-template-columns: 1fr;
                }}
                .stats-row {{
                    grid-template-columns: repeat(2, 1fr);
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔐 Admin Control Panel</h1>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </header>

            <div class="tabs">
                <button class="tab-button active" onclick="switchTab('overview')">📊 Overview</button>
                <button class="tab-button" onclick="switchTab('pending')">⏳ Pending Approval ({len(pending_devices)})</button>
                <button class="tab-button" onclick="switchTab('approved')">✓ Approved Devices ({len(whitelist['whitelisted_ips'])})</button>
                <button class="tab-button" onclick="switchTab('sessions')">● Active Sessions ({len(active_sessions.get('active_sessions', {}))})</button>
                <button class="tab-button" onclick="switchTab('graphs')">📈 Collatz Graphs</button>
            </div>

            <!-- Overview Tab -->
            <div id="overview" class="tab-content active">
                <h2 style="margin-bottom: 20px; color: #333;">System Overview</h2>
                {stats_html}
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                <h3 style="margin-bottom: 20px; color: #333;">Quick Summary</h3>
                <div class="devices-grid">
                    <div class="device-card">
                        <h4 style="color: #0078d4; margin-bottom: 10px;">Pending Devices</h4>
                        {pending_html}
                    </div>
                    <div class="device-card">
                        <h4 style="color: #4caf50; margin-bottom: 10px;">Recent Approvals</h4>
                        {whitelisted_html if len(whitelist['whitelisted_ips']) <= 2 else '<p style="color: #999;">Showing in Approved Devices tab</p>'}
                    </div>
                </div>
            </div>

            <!-- Pending Devices Tab -->
            <div id="pending" class="tab-content">
                <h2 style="margin-bottom: 20px; color: #333;">Pending Device Approvals</h2>
                <div class="devices-grid">
                    {pending_html}
                </div>
            </div>

            <!-- Approved Devices Tab -->
            <div id="approved" class="tab-content">
                <h2 style="margin-bottom: 20px; color: #333;">Approved & Whitelisted Devices</h2>
                <div class="devices-grid">
                    {whitelisted_html}
                </div>
            </div>

            <!-- Active Sessions Tab -->
            <div id="sessions" class="tab-content">
                <h2 style="margin-bottom: 20px; color: #333;">Active Sessions</h2>
                {sessions_html}
            </div>

            <!-- Collatz Graphs Tab -->
            <div id="graphs" class="tab-content">
                <h2 style="margin-bottom: 20px; color: #333;">Collatz Sequence Visualization</h2>
                {collatz_charts if collatz_charts else '<div class="no-data">No Collatz data available</div>'}
            </div>
        </div>

        <script>
            function switchTab(tabName) {{
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {{
                    tab.classList.remove('active');
                }});
                document.querySelectorAll('.tab-button').forEach(btn => {{
                    btn.classList.remove('active');
                }});

                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
            }}

            function approveDevice(ip) {{
                if (confirm('Approve device ' + ip + '?')) {{
                    fetch('/analytics/api/admin/approve/', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ip_address: ip}})
                    }}).then(r => r.json()).then(d => {{
                        alert(d.message);
                        location.reload();
                    }});
                }}
            }}

            function rejectDevice(ip) {{
                if (confirm('Reject device ' + ip + '?')) {{
                    fetch('/analytics/api/admin/reject/', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ip_address: ip}})
                    }}).then(r => r.json()).then(d => {{
                        alert(d.message);
                        location.reload();
                    }});
                }}
            }}

            function removeWhitelist(ip) {{
                if (confirm('Remove whitelisted device ' + ip + '?')) {{
                    fetch('/analytics/api/whitelist/remove/', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{ip_address: ip}})
                    }}).then(r => r.json()).then(d => {{
                        alert(d.message);
                        location.reload();
                    }});
                }}
            }}

            function logout() {{
                if (confirm('Logout?')) {{
                    window.location.href = '/analytics/admin/login/';
                }}
            }}
        </script>
    </body>
    </html>
    """

    return html


def get_dashboard_html(pending_devices, whitelist, stats, active_sessions):
    """Generate main dashboard HTML"""
    # Build pending devices HTML
    pending_html = ""
    if pending_devices:
        for ip, info in pending_devices.items():
            pending_html += f"""
            <div class="device-card">
                <div class="device-header">
                    <span class="device-type-badge">{info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge pending">PENDING</span>
                </div>
                <div class="device-details">
                    <p><strong>Requested:</strong> {info.get('timestamp', 'N/A')}</p>
                </div>
                <div class="device-actions">
                    <button class="btn-approve" onclick="approveDevice('{ip}')">✓ Approve</button>
                    <button class="btn-reject" onclick="rejectDevice('{ip}')">✗ Reject</button>
                </div>
            </div>
            """
    else:
        pending_html = '<p style="color: #999; text-align: center;">No pending devices</p>'

    # Build whitelisted devices HTML
    whitelisted_html = ""
    if whitelist['whitelisted_ips']:
        for ip in whitelist['whitelisted_ips']:
            device_info = analytics_engine.device_registry.get(ip, {})
            whitelist_entry = whitelist['whitelist_data'].get(ip, {})
            hash_value = whitelist_entry.get('hash', 'N/A')

            seq_info = analytics_engine.get_collatz_sequence_for_ip(ip)
            sequence = seq_info.get('sequence', []) if seq_info.get('found') else []
            sequence_display = ', '.join(str(n) for n in sequence[:10])
            if len(sequence) > 10:
                sequence_display += f", ... ({len(sequence)} total)"

            whitelisted_html += f"""
            <div class="whitelisted-item">
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="device-type-badge">{device_info.get('device_type', 'Unknown')}</span>
                        <span class="device-ip">{ip}</span>
                        <span class="status-badge approved">✓ APPROVED</span>
                    </div>
                    <div class="hash-display">
                        <small>SHA1-E3 Hash:</small>
                        <code style="display: block; font-size: 11px; color: #4caf50; margin-top: 4px; word-break: break-all;">{hash_value}</code>
                    </div>
                    <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(76, 175, 80, 0.2);">
                        <small>Collatz Sequence:</small>
                        <code style="display: block; font-size: 10px; color: #88ccff; margin-top: 4px; word-break: break-all;">{sequence_display}</code>
                    </div>
                </div>
                <button class="btn-remove" onclick="removeWhitelist('{ip}')">Remove</button>
            </div>
            """
    else:
        whitelisted_html = '<p style="color: #999; text-align: center;">No approved devices</p>'

    # Build active sessions HTML
    active_sessions_html = ""
    if active_sessions['active_sessions']:
        for ip, session_info in active_sessions['active_sessions'].items():
            first_access = session_info.get('first_access', 'N/A')[:19]
            last_access = session_info.get('last_access', 'N/A')[:19]
            access_count = session_info.get('access_count', 0)

            active_sessions_html += f"""
            <div class="session-card">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                    <span class="device-type-badge">{session_info.get('device_type', 'Unknown')}</span>
                    <span class="device-ip">{ip}</span>
                    <span class="status-badge approved">● ACTIVE</span>
                </div>
                <div style="color: #666; font-size: 12px;">
                    <p><strong>Requests:</strong> {access_count}</p>
                    <p><strong>First Access:</strong> {first_access}</p>
                    <p><strong>Last Access:</strong> {last_access}</p>
                </div>
            </div>
            """
    else:
        active_sessions_html = '<p style="color: #999; text-align: center;">No active sessions</p>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firewall Gateway - Admin Dashboard</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: #f3f3f3;
                color: #333;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
                min-height: 100vh;
            }}
            .navbar {{
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(0, 0, 0, 0.06);
                padding: 0;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 0 20px;
            }}
            .nav-brand {{
                font-size: 18px;
                font-weight: 600;
                color: #0078d4;
                padding: 16px 0;
            }}
            .nav-links {{
                display: flex;
                gap: 0;
            }}
            .nav-link {{
                color: #333;
                text-decoration: none;
                padding: 12px 20px;
                border-bottom: 3px solid transparent;
                font-size: 13px;
                font-weight: 500;
                transition: all 0.2s;
                cursor: pointer;
            }}
            .nav-link:hover {{
                color: #0078d4;
            }}
            .nav-link.active {{
                color: #0078d4;
                border-bottom-color: #0078d4;
            }}
            .logout-btn {{
                background: #f3f3f3;
                color: #d13438;
                border: 1px solid #d13438;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
                transition: all 0.2s;
            }}
            .logout-btn:hover {{
                background: #d13438;
                color: white;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}
            .page {{
                display: none;
            }}
            .page.active {{
                display: block;
            }}
            .stats-row {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 16px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: rgba(255, 255, 255, 0.7);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 12px;
                padding: 24px 20px;
                text-align: center;
                transition: all 0.25s;
                cursor: pointer;
                position: relative;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            }}
            .stat-card:hover {{
                transform: translateY(-4px);
                border-color: rgba(0, 120, 212, 0.3);
                box-shadow: 0 4px 12px rgba(0, 120, 212, 0.15);
                background: rgba(255, 255, 255, 0.9);
            }}
            .stat-number {{
                color: #0078d4;
                font-size: 36px;
                font-weight: 700;
                margin: 12px 0 8px;
            }}
            .stat-label {{
                color: #666;
                font-size: 13px;
                font-weight: 500;
            }}
            .panels {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-top: 20px;
            }}
            .panel {{
                background: rgba(255, 255, 255, 0.7);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 12px;
                padding: 24px;
                transition: all 0.25s;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            }}
            .panel:hover {{
                border-color: rgba(0, 120, 212, 0.3);
                box-shadow: 0 4px 12px rgba(0, 120, 212, 0.1);
            }}
            .panel h2 {{
                color: #0078d4;
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 16px;
                padding-bottom: 12px;
                border-bottom: 1px solid rgba(0, 0, 0, 0.06);
            }}
            .device-card {{
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 12px;
                transition: all 0.2s;
            }}
            .device-card:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
                transform: translateX(3px);
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
            }}
            .device-header {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 10px;
            }}
            .device-type-badge {{
                background: #e7f0f7;
                color: #0078d4;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
            }}
            .device-ip {{
                font-weight: 600;
                color: #0078d4;
                flex: 1;
                font-size: 14px;
            }}
            .status-badge {{
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
            }}
            .status-badge.pending {{
                background: #fef3cd;
                color: #856404;
            }}
            .status-badge.approved {{
                background: #d4edda;
                color: #155724;
            }}
            .device-details {{
                color: #666;
                font-size: 12px;
                margin: 8px 0;
            }}
            .device-actions {{
                display: flex;
                gap: 8px;
                margin-top: 10px;
            }}
            .btn-approve, .btn-reject, .btn-remove {{
                padding: 8px 16px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
                transition: all 0.2s;
                font-weight: 500;
            }}
            .btn-approve {{
                background: #107c10;
                color: white;
            }}
            .btn-approve:hover {{
                background: #0b6a0b;
                box-shadow: 0 2px 8px rgba(16, 124, 16, 0.2);
            }}
            .btn-reject {{
                background: #f7630c;
                color: white;
            }}
            .btn-reject:hover {{
                background: #da5a00;
                box-shadow: 0 2px 8px rgba(247, 99, 12, 0.2);
            }}
            .btn-remove {{
                background: #d13438;
                color: white;
                margin-left: auto;
            }}
            .btn-remove:hover {{
                background: #a4373a;
                box-shadow: 0 2px 8px rgba(209, 52, 56, 0.2);
            }}
            .whitelisted-item {{
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 12px;
                transition: all 0.2s;
            }}
            .whitelisted-item:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
            }}
            .hash-display {{
                background: rgba(16, 124, 16, 0.08);
                padding: 12px;
                border-left: 3px solid #107c10;
                border-radius: 4px;
                margin: 10px 0;
            }}
            .hash-display code {{
                background: rgba(0, 0, 0, 0.05);
                padding: 6px 8px;
                border-radius: 4px;
                font-size: 11px;
                color: #0078d4;
                font-family: 'Courier New', monospace;
            }}
            .session-card {{
                background: rgba(255, 255, 255, 0.5);
                border: 1px solid rgba(0, 0, 0, 0.06);
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 12px;
                transition: all 0.2s;
            }}
            .session-card:hover {{
                background: rgba(255, 255, 255, 0.8);
                border-color: rgba(0, 120, 212, 0.2);
            }}
            .message {{
                padding: 14px 16px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
                font-size: 13px;
                font-weight: 500;
                animation: slideDown 0.3s ease-out;
            }}
            @keyframes slideDown {{
                from {{
                    opacity: 0;
                    transform: translateY(-10px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            .message.success {{
                background: rgba(16, 124, 16, 0.1);
                border: 1px solid rgba(16, 124, 16, 0.3);
                color: #107c10;
            }}
            .message.error {{
                background: rgba(209, 52, 56, 0.1);
                border: 1px solid rgba(209, 52, 56, 0.3);
                color: #d13438;
            }}
            @media (max-width: 1024px) {{
                .panels {{ grid-template-columns: 1fr; }}
                .nav-links {{ display: none; }}
            }}
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="nav-container">
                <div class="nav-brand">🔐 Firewall Gateway</div>
                <div class="nav-links">
                    <a class="nav-link active" onclick="switchPage('dashboard')">Dashboard</a>
                    <a class="nav-link" onclick="switchPage('collatz')">Collatz Graphs</a>
                    <a class="nav-link" onclick="switchPage('insights')">User Insights</a>
                </div>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>

        <div class="container">
            <div id="message" class="message"></div>

            <!-- Dashboard Page -->
            <div id="dashboard" class="page active">
                <div class="stats-row">
                    <div class="stat-card">
                        <div class="stat-label">Total Devices</div>
                        <div class="stat-number">{stats['total_devices']}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Approved</div>
                        <div class="stat-number">{stats['whitelisted_devices']}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Pending</div>
                        <div class="stat-number">{stats['pending_devices']}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Active Users</div>
                        <div class="stat-number">{active_sessions['count']}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Verifications</div>
                        <div class="stat-number">{stats['total_verifications']}</div>
                    </div>
                </div>

                <div class="panels">
                    <div class="panel">
                        <h2>⏳ Pending Device Approvals ({len(pending_devices)})</h2>
                        {pending_html}
                    </div>
                    <div class="panel">
                        <h2>✓ Approved Devices ({len(whitelist['whitelisted_ips'])})</h2>
                        {whitelisted_html}
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <div class="panel">
                        <h2>🟢 Currently Active Service Users ({active_sessions['count']})</h2>
                        {active_sessions_html}
                    </div>
                </div>
            </div>

            <!-- Collatz Graphs Page -->
            <div id="collatz" class="page">
                <div class="panel">
                    <h2>📊 Collatz Sequence Visualizations</h2>
                    <div id="collatz-container" style="min-height: 400px; padding: 20px;">
                        <p style="text-align: center; color: #999;">Loading graphs...</p>
                    </div>
                </div>
            </div>

            <!-- User Insights Page -->
            <div id="insights" class="page">
                <div class="panel">
                    <h2>📈 User Session Analytics</h2>
                    <div id="insights-container" style="min-height: 400px; padding: 20px;">
                        <p style="text-align: center; color: #999;">Loading analytics...</p>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            function switchPage(page) {{
                // Hide all pages
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

                // Show selected page
                document.getElementById(page).classList.add('active');

                // Update nav links
                document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
                event.target.classList.add('active');

                // Load page-specific data
                if (page === 'collatz') {{
                    loadCollatzGraphs();
                }} else if (page === 'insights') {{
                    loadUserInsights();
                }}
            }}

            function loadCollatzGraphs() {{
                fetch('/analytics/api/collatz-graphs/')
                    .then(r => r.json())
                    .then(data => {{
                        if (data.success) {{
                            renderCollatzGraphs(data.devices);
                        }}
                    }})
                    .catch(e => console.error(e));
            }}

            function loadUserInsights() {{
                fetch('/analytics/api/user-insights/')
                    .then(r => r.json())
                    .then(data => {{
                        if (data.success) {{
                            renderUserInsights(data.insights);
                        }}
                    }})
                    .catch(e => console.error(e));
            }}

            function renderCollatzGraphs(devices) {{
                let html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px;">';

                devices.forEach((device, idx) => {{
                    html += `
                        <div style="background: rgba(255,255,255,0.5); border: 1px solid rgba(0,0,0,0.06); border-radius: 8px; padding: 16px;">
                            <h3 style="color: #0078d4; margin-bottom: 12px;">${{device.device_type}} - ${{device.ip}}</h3>
                            <canvas id="chart-${{idx}}"></canvas>
                        </div>
                    `;
                }});

                html += '</div>';
                document.getElementById('collatz-container').innerHTML = html;

                // Draw charts
                devices.forEach((device, idx) => {{
                    const ctx = document.getElementById(`chart-${{idx}}`);
                    new Chart(ctx, {{
                        type: 'line',
                        data: {{
                            labels: device.sequence.map((_, i) => i),
                            datasets: [{{
                                label: 'Collatz Sequence',
                                data: device.sequence,
                                borderColor: '#0078d4',
                                backgroundColor: 'rgba(0, 120, 212, 0.1)',
                                tension: 0.1,
                                fill: true,
                                pointRadius: 2,
                                pointBackgroundColor: '#107c10'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            plugins: {{
                                legend: {{ display: true }},
                                title: {{ display: false }}
                            }},
                            scales: {{
                                y: {{ beginAtZero: true }}
                            }}
                        }}
                    }});
                }});
            }}

            function renderUserInsights(insights) {{
                let html = '<table style="width: 100%; border-collapse: collapse;">';
                html += `
                    <thead>
                        <tr style="border-bottom: 2px solid rgba(0,0,0,0.06);">
                            <th style="padding: 12px; text-align: left; color: #0078d4; font-weight: 600;">Device</th>
                            <th style="padding: 12px; text-align: left; color: #0078d4; font-weight: 600;">Type</th>
                            <th style="padding: 12px; text-align: left; color: #0078d4; font-weight: 600;">First Access</th>
                            <th style="padding: 12px; text-align: left; color: #0078d4; font-weight: 600;">Duration</th>
                            <th style="padding: 12px; text-align: left; color: #0078d4; font-weight: 600;">Requests</th>
                        </tr>
                    </thead>
                    <tbody>
                `;

                insights.forEach(insight => {{
                    const hours = insight.duration_seconds / 3600;
                    const minutes = (insight.duration_seconds % 3600) / 60;
                    const duration = `${{Math.floor(hours)}}h ${{Math.floor(minutes)}}m`;

                    html += `
                        <tr style="border-bottom: 1px solid rgba(0,0,0,0.06);">
                            <td style="padding: 12px;">${{insight.ip}}</td>
                            <td style="padding: 12px;"><span style="background: #e7f0f7; color: #0078d4; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">${{insight.device_type}}</span></td>
                            <td style="padding: 12px;">${{insight.first_access}}</td>
                            <td style="padding: 12px;">${{duration}}</td>
                            <td style="padding: 12px;"><strong>${{insight.access_count}}</strong></td>
                        </tr>
                    `;
                }});

                html += '</tbody></table>';
                document.getElementById('insights-container').innerHTML = html;
            }}

            function approveDevice(ip) {{
                if (!confirm(`Approve device ${{ip}}?`)) return;

                fetch('/analytics/api/admin/approve/', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken')
                    }},
                    body: JSON.stringify({{ ip_address: ip }})
                }}).then(r => r.json()).then(data => {{
                    showMessage(data.success ? 'Device approved!' : 'Failed: ' + data.message, data.success ? 'success' : 'error');
                    if (data.success) setTimeout(() => location.reload(), 1500);
                }});
            }}

            function rejectDevice(ip) {{
                if (!confirm(`Reject device ${{ip}}?`)) return;

                fetch('/analytics/api/admin/reject/', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken')
                    }},
                    body: JSON.stringify({{ ip_address: ip }})
                }}).then(r => r.json()).then(data => {{
                    showMessage(data.success ? 'Device rejected!' : 'Failed: ' + data.message, data.success ? 'success' : 'error');
                    if (data.success) setTimeout(() => location.reload(), 1500);
                }});
            }}

            function removeWhitelist(ip) {{
                if (!confirm(`Remove ${{ip}} from whitelist?`)) return;

                fetch('/analytics/api/whitelist/remove/', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken')
                    }},
                    body: JSON.stringify({{ ip_address: ip }})
                }}).then(r => r.json()).then(data => {{
                    showMessage(data.success ? 'Device removed!' : 'Failed: ' + data.message, data.success ? 'success' : 'error');
                    if (data.success) setTimeout(() => location.reload(), 1500);
                }});
            }}

            function logout() {{
                if (confirm('Logout?')) {{
                    window.location.href = '/analytics/admin/login/';
                }}
            }}

            function showMessage(text, type) {{
                const msg = document.getElementById('message');
                msg.textContent = text;
                msg.className = 'message ' + type;
                msg.style.display = 'block';
                setTimeout(() => msg.style.display = 'none', 5000);
            }}

            function getCookie(name) {{
                let cookieValue = null;
                if (document.cookie) {{
                    const cookies = document.cookie.split(';');
                    for (let cookie of cookies) {{
                        const [cname, cvalue] = cookie.trim().split('=');
                        if (cname === name) cookieValue = decodeURIComponent(cvalue);
                    }}
                }}
                return cookieValue;
            }}

            // Auto-refresh every 30 seconds
            setInterval(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    """

    return html


def get_collatz_graph_html(devices_data):
    """Generate Collatz graphs HTML with Chart.js"""
    # Build chart data for each device
    charts_html = ""

    for device in devices_data:
        ip = device['ip']
        device_type = device['device_type']
        sequence = device['sequence']

        if sequence:
            # Create a chart for this device
            chart_id = f"chart_{ip.replace('.', '_')}"
            charts_html += f"""
            <div class="chart-container">
                <h3>{ip} ({device_type})</h3>
                <div style="position: relative; height: 300px;">
                    <canvas id="{chart_id}"></canvas>
                </div>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    <p><strong>Sequence Length:</strong> {len(sequence)}</p>
                    <p><strong>Max Value:</strong> {max(sequence) if sequence else 0}</p>
                </div>
            </div>
            """

    if not charts_html:
        charts_html = '<p style="color: #999; text-align: center; padding: 40px;">No approved devices yet</p>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Collatz Graphs - Firewall Gateway</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: #f3f3f3;
                color: #333;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
                min-height: 100vh;
            }}
            .navbar {{
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(0, 0, 0, 0.06);
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
                padding: 0;
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 0 20px;
            }}
            .nav-brand {{
                font-size: 18px;
                font-weight: 600;
                color: #0078d4;
                padding: 16px 0;
            }}
            .nav-links {{
                display: flex;
                gap: 0;
            }}
            .nav-link {{
                color: #333;
                text-decoration: none;
                padding: 12px 20px;
                border-bottom: 3px solid transparent;
                font-size: 13px;
                font-weight: 500;
                transition: all 0.2s;
                cursor: pointer;
            }}
            .nav-link:hover {{
                color: #0078d4;
            }}
            .nav-link.active {{
                color: #0078d4;
                border-bottom-color: #0078d4;
            }}
            .logout-btn {{
                background: #f3f3f3;
                color: #d13438;
                border: 1px solid #d13438;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}
            .chart-container {{
                background: white;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            }}
            .chart-container h3 {{
                color: #0078d4;
                margin-bottom: 15px;
            }}
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="nav-container">
                <div class="nav-brand">🔐 Firewall Gateway</div>
                <div class="nav-links">
                    <a class="nav-link" onclick="window.location.href='/analytics/admin/dashboard/'">Dashboard</a>
                    <a class="nav-link active" onclick="window.location.href='/analytics/admin/collatz-graphs/'">Collatz Graphs</a>
                    <a class="nav-link" onclick="window.location.href='/analytics/admin/user-insights/'">User Insights</a>
                </div>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>

        <div class="container">
            <h1 style="margin-bottom: 20px; color: #0078d4;">Collatz Sequence Visualization</h1>
            {charts_html}
        </div>

        <script>
            function logout() {{
                if (confirm('Logout?')) {{
                    window.location.href = '/analytics/admin/login/';
                }}
            }}

            // Render charts for each device
            const devicesData = {json.dumps(devices_data)};

            devicesData.forEach(device => {{
                const chartId = 'chart_' + device.ip.replace(/\\./g, '_');
                const canvas = document.getElementById(chartId);
                if (canvas) {{
                    new Chart(canvas, {{
                        type: 'line',
                        data: {{
                            labels: Array.from({{length: device.sequence.length}}, (_, i) => i),
                            datasets: [{{
                                label: 'Collatz Sequence - ' + device.ip,
                                data: device.sequence,
                                borderColor: '#0078d4',
                                backgroundColor: 'rgba(0, 120, 212, 0.1)',
                                borderWidth: 2,
                                tension: 0.1,
                                fill: true
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    display: true,
                                    position: 'top'
                                }}
                            }},
                            scales: {{
                                y: {{
                                    beginAtZero: true
                                }}
                            }}
                        }}
                    }});
                }}
            }});

            // Auto-refresh every 30 seconds
            setInterval(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    """

    return html


def get_user_insights_html(insights_data):
    """Generate User Insights HTML with session analytics table"""
    # Build table rows for each active session
    table_rows = ""

    if insights_data:
        for insight in insights_data:
            ip = insight['ip']
            device_type = insight['device_type']
            first_access = insight['first_access']
            last_access = insight['last_access']
            duration_seconds = insight['duration_seconds']
            duration_hours = insight['duration_hours']
            access_count = insight['access_count']

            # Format duration nicely
            hours = duration_seconds // 3600
            minutes = (duration_seconds % 3600) // 60
            seconds = duration_seconds % 60
            duration_str = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"

            table_rows += f"""
            <tr>
                <td>{ip}</td>
                <td><span style="background: #e8f4f8; padding: 4px 8px; border-radius: 4px; font-size: 12px;">{device_type}</span></td>
                <td>{first_access}</td>
                <td>{last_access}</td>
                <td>{duration_str}</td>
                <td style="text-align: center; color: #0078d4; font-weight: 500;">{access_count}</td>
            </tr>
            """
    else:
        table_rows = '<tr><td colspan="6" style="text-align: center; color: #999; padding: 40px;">No active sessions</td></tr>'

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Insights - Firewall Gateway</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                background: #f3f3f3;
                color: #333;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
                min-height: 100vh;
            }}
            .navbar {{
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(0, 0, 0, 0.06);
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
                padding: 0;
                position: sticky;
                top: 0;
                z-index: 100;
            }}
            .nav-container {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 0 20px;
            }}
            .nav-brand {{
                font-size: 18px;
                font-weight: 600;
                color: #0078d4;
                padding: 16px 0;
            }}
            .nav-links {{
                display: flex;
                gap: 0;
            }}
            .nav-link {{
                color: #333;
                text-decoration: none;
                padding: 12px 20px;
                border-bottom: 3px solid transparent;
                font-size: 13px;
                font-weight: 500;
                transition: all 0.2s;
                cursor: pointer;
            }}
            .nav-link:hover {{
                color: #0078d4;
            }}
            .nav-link.active {{
                color: #0078d4;
                border-bottom-color: #0078d4;
            }}
            .logout-btn {{
                background: #f3f3f3;
                color: #d13438;
                border: 1px solid #d13438;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 500;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}
            .table-container {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
                overflow: hidden;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            thead {{
                background: #f5f5f5;
                border-bottom: 2px solid #e0e0e0;
            }}
            th {{
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #0078d4;
                font-size: 13px;
            }}
            td {{
                padding: 12px;
                border-bottom: 1px solid #e0e0e0;
                font-size: 13px;
            }}
            tbody tr:hover {{
                background: #f9f9f9;
            }}
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="nav-container">
                <div class="nav-brand">🔐 Firewall Gateway</div>
                <div class="nav-links">
                    <a class="nav-link" onclick="window.location.href='/analytics/admin/dashboard/'">Dashboard</a>
                    <a class="nav-link" onclick="window.location.href='/analytics/admin/collatz-graphs/'">Collatz Graphs</a>
                    <a class="nav-link active" onclick="window.location.href='/analytics/admin/user-insights/'">User Insights</a>
                </div>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>

        <div class="container">
            <h1 style="margin-bottom: 20px; color: #0078d4;">Session Analytics & User Insights</h1>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Device IP</th>
                            <th>Type</th>
                            <th>First Access</th>
                            <th>Last Access</th>
                            <th>Duration</th>
                            <th>Requests</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            function logout() {{
                if (confirm('Logout?')) {{
                    window.location.href = '/analytics/admin/login/';
                }}
            }}

            // Auto-refresh every 30 seconds
            setInterval(() => location.reload(), 30000);
        </script>
    </body>
    </html>
    """

    return html
