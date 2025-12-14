# Unified Admin Panel - Quick Reference Guide

## 🚀 Quick Start (60 seconds)

```bash
# 1. Start server
python manage.py runserver 0.0.0.0:8000

# 2. Open browser
# http://localhost:8000/analytics/admin/login/

# 3. Login
# Username: admin
# Password: firewall_gateway_2025

# 4. View admin panel
# http://localhost:8000/analytics/admin/
```

---

## 📋 Main URLs

| Purpose | URL |
|---------|-----|
| Login | `http://localhost:8000/analytics/admin/login/` |
| Admin Panel | `http://localhost:8000/analytics/admin/` |
| Dashboard (same) | `http://localhost:8000/analytics/admin/dashboard/` |
| Collatz Graphs (same) | `http://localhost:8000/analytics/admin/collatz-graphs/` |
| User Insights (same) | `http://localhost:8000/analytics/admin/user-insights/` |

---

## 🔐 Credentials

```
Username: admin
Password: firewall_gateway_2025
```

---

## 5️⃣ Interface Tabs

### 📊 Overview Tab
- System statistics
- Device counts
- Approval workflow summary

### ⏳ Pending Approval Tab
- Devices awaiting approval
- Click ✅ to approve
- Click ❌ to reject

### ✓ Approved Devices Tab
- Whitelisted devices
- SHA1-E3 hashes
- Collatz sequences
- Click 🗑️ to remove

### ● Active Sessions Tab
- Currently online devices
- Request counts
- Activity timestamps

### 📈 Collatz Graphs Tab
- Interactive visualizations
- Line graphs per device
- Hash displays

---

## 🔌 API Quick Reference

### Login
```bash
curl -X POST http://localhost:8000/analytics/api/admin/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"firewall_gateway_2025"}'
```

### Get Approved Devices
```bash
TOKEN="your_token"
curl http://localhost:8000/analytics/api/whitelist/list/ \
  -b "admin_token=$TOKEN"
```

### Get Pending Devices
```bash
TOKEN="your_token"
curl http://localhost:8000/analytics/api/pending/ \
  -b "admin_token=$TOKEN"
```

### Approve Device
```bash
TOKEN="your_token"
curl -X POST http://localhost:8000/analytics/api/admin/approve/ \
  -H "Content-Type: application/json" \
  -b "admin_token=$TOKEN" \
  -d '{"ip_address":"192.168.1.100"}'
```

### Reject Device
```bash
TOKEN="your_token"
curl -X POST http://localhost:8000/analytics/api/admin/reject/ \
  -H "Content-Type: application/json" \
  -b "admin_token=$TOKEN" \
  -d '{"ip_address":"192.168.1.100"}'
```

### Get All Registered Devices
```bash
TOKEN="your_token"
curl http://localhost:8000/analytics/api/devices/ \
  -b "admin_token=$TOKEN"
```

### Get Active Sessions
```bash
TOKEN="your_token"
curl http://localhost:8000/analytics/api/sessions/ \
  -b "admin_token=$TOKEN"
```

### Get Collatz Sequence
```bash
TOKEN="your_token"
curl http://localhost:8000/analytics/api/collatz/127.0.0.1/ \
  -b "admin_token=$TOKEN"
```

---

## 📁 Data Files

All data persists in: `firewall_gateway/analytics/data/`

| File | Purpose |
|------|---------|
| `whitelist.json` | Approved devices |
| `device_registry.json` | All registered devices |
| `pending_devices.json` | Devices awaiting approval |
| `collatz_sequences.json` | Collatz sequences & hashes |
| `active_sessions.json` | Current user sessions |
| `admin_sessions.json` | Admin login sessions |

---

## 🔍 Viewing Data Files

```bash
# Check what devices are approved
cat firewall_gateway/analytics/data/whitelist.json

# Check all registered devices
cat firewall_gateway/analytics/data/device_registry.json

# Check pending devices
cat firewall_gateway/analytics/data/pending_devices.json

# Check active sessions
cat firewall_gateway/analytics/data/active_sessions.json

# Check admin sessions
cat firewall_gateway/analytics/data/admin_sessions.json
```

---

## ⚙️ Configuration

### Change Admin Password

1. Edit `firewall_gateway/analytics/analytics_engine.py`
2. Find line ~83:
```python
self.admin_credentials = {
    'username': 'admin',
    'password': 'firewall_gateway_2025'  # ← Change this
}
```
3. Restart server

### Change Session Expiration

1. Edit `firewall_gateway/analytics/analytics_engine.py`
2. Find `login_admin()` method:
```python
'expires': (datetime.now() + timedelta(hours=8)).isoformat()  # ← Change 8 to desired hours
```
3. Restart server

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| "Unauthorized" error | Login again, clear cookies, check admin_token expiry |
| Data not persisting | Check directory permissions, verify JSON files exist |
| Device list empty | Check device_registry.json, re-register device |
| Charts not showing | Verify Chart.js CDN accessible, check browser console |
| Import errors | Ensure lazy imports in views_dashboard.py |

---

## 📊 Current System Status

**Approved Devices:** 2
- 127.0.0.1 (iOS)
- 10.89.198.97 (Android)

**Pending Devices:** 0

**Active Sessions:** 1
- 10.89.198.97 (Android)

---

## 🔐 Security Checklist

- [ ] Change default admin password
- [ ] Use HTTPS in production
- [ ] Backup data files regularly
- [ ] Monitor admin_sessions.json
- [ ] Implement rate limiting
- [ ] Use strong passwords

---

## 📞 Support Resources

- **Main Documentation:** `UNIFIED_ADMIN_PANEL_DOCUMENTATION.md`
- **Code Files:**
  - `firewall_gateway/analytics/views_dashboard.py`
  - `firewall_gateway/analytics/views.py`
  - `firewall_gateway/analytics/analytics_engine.py`
- **GitHub:** https://github.com/vineshhazy/firewall-gateway

---

## 🎯 Common Tasks

### Add a New Admin User

*Not yet implemented - requires database*

### Export Device List

*Use `/analytics/api/devices/` endpoint and save JSON*

### Bulk Approve Devices

*Not yet implemented - requires UI enhancement*

### View Device History

*Currently shows current state - consider adding audit logs*

### Monitor Device Activity

Use **Active Sessions** tab or call `/analytics/api/sessions/`

---

## 💡 Tips & Tricks

1. **Use curl for automation:** Save auth token in environment variable
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8000/analytics/api/admin/login/ \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"firewall_gateway_2025"}' | jq -r '.session_token')
   ```

2. **Monitor in real-time:** Use watch command
   ```bash
   watch -n 5 'cat firewall_gateway/analytics/data/active_sessions.json'
   ```

3. **Backup data regularly:**
   ```bash
   cp -r firewall_gateway/analytics/data/ backups/data_$(date +%Y%m%d_%H%M%S)/
   ```

4. **Pretty-print JSON:**
   ```bash
   python -m json.tool firewall_gateway/analytics/data/whitelist.json
   ```

---

**Last Updated:** December 13, 2025
**Version:** 1.0
**Status:** ✅ Ready

