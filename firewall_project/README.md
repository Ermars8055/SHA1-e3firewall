# Firewall Gateway Project

Independent Django project for the Collatz Firewall Gateway system.

## Structure

```
firewall_project/
├── manage.py                    # Django management script
├── firewall_project_main/       # Main Django project configuration
│   ├── settings.py             # Django settings
│   ├── urls.py                 # URL routing
│   ├── wsgi.py                 # WSGI application
│   └── __init__.py
├── firewall_gateway/           # Main firewall application
│   ├── analytics/              # Analytics dashboard and API
│   ├── api/                    # API endpoints
│   ├── core/                   # Core firewall logic
│   ├── middleware/             # Django middleware
│   ├── models/                 # Database models
│   ├── utils/                  # Utility functions
│   └── tests/                  # Test suite
└── db.sqlite3                  # Development database
```

## Running the Project

```bash
cd /Users/admin/Desktop/SHA10-Test/firewall_project

# Run migrations
python manage.py migrate

# Start development server
python manage.py runserver 8000

# Access dashboard
# http://localhost:8000/analytics/
```

## API Endpoints

- `GET /analytics/api/stats/` - Get current statistics
- `GET /analytics/api/patterns/` - Get detected patterns
- `GET /analytics/api/innovations/` - Get innovation suggestions
- `GET /analytics/api/verifications/` - Get recent verifications
- `POST /analytics/api/record/` - Record verification event
- `GET /analytics/api/health/` - Health check

## Dashboard

Analytics dashboard available at `/analytics/` with real-time updates every 2 seconds.
