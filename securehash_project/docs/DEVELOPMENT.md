# Development Environment Setup Guide

## Prerequisites

1. **Python Environment:**
   - Python 3.10 or higher
   - pip package manager
   - virtualenv or venv module

2. **System Tools:**
   - Git
   - Text editor or IDE (VS Code recommended)
   - Terminal access

## Initial Setup

1. **Clone the Repository:**
```bash
git clone <repository-url>
cd securehash_project
```

2. **Create Virtual Environment:**
```bash
# Using venv
python3 -m venv venv

# Activate virtual environment
# On Unix/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate
```

3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

## IDE Configuration

### VS Code Setup

1. **Required Extensions:**
   - Python (ms-python.python)
   - Pylance (ms-python.vscode-pylance)
   - Django (batisteo.vscode-django)

2. **Recommended Settings:**
```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "python.testing.pytestEnabled": true
}
```

3. **Launch Configurations:**
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Django",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/manage.py",
            "args": ["runserver"],
            "django": true
        },
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal"
        }
    ]
}
```

## Development Workflow

1. **Run Tests:**
```bash
# Run all tests
pytest

# Run specific test file
pytest storage/tests/test_merkle_tree.py

# Run with coverage
pytest --cov=storage
```

2. **Code Style:**
```bash
# Install development tools
pip install black pylint mypy

# Format code
black .

# Run linter
pylint storage/

# Type checking
mypy storage/
```

3. **Django Development:**
```bash
# Make migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Run development server
python manage.py runserver
```

4. **CLI Tool Development:**
```bash
# Run CLI tool
python scripts/collatz_sig.py --help

# Development mode
python -m pdb scripts/collatz_sig.py compute test.txt
```

## Debugging Tips

1. **Django Debug Toolbar:**
   - Install: `pip install django-debug-toolbar`
   - Add to INSTALLED_APPS
   - Configure URLs

2. **Logging Configuration:**
```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

3. **VS Code Debugging:**
   - Set breakpoints
   - Use watch expressions
   - Inspect variables

## Common Issues

1. **Virtual Environment:**
   - Ensure activation before pip install
   - Check Python version matches project
   - Verify PATH settings

2. **Django Setup:**
   - Check settings.py configuration
   - Verify database connections
   - Review INSTALLED_APPS

3. **Testing:**
   - Ensure pytest.ini is present
   - Check test discovery paths
   - Verify fixture availability

## Performance Profiling

1. **cProfile Usage:**
```python
import cProfile
profiler = cProfile.Profile()
profiler.enable()
# Code to profile
profiler.disable()
profiler.print_stats(sort='cumtime')
```

2. **Memory Profiling:**
```bash
pip install memory_profiler
python -m memory_profiler scripts/collatz_sig.py
```

## Deployment Preparation

1. **Security Checklist:**
   - Remove debug settings
   - Update SECRET_KEY
   - Configure ALLOWED_HOSTS

2. **Performance Optimization:**
   - Enable caching
   - Optimize database queries
   - Configure static files

3. **Documentation:**
   - Update README.md
   - Document API changes
   - Update CHANGELOG.md
