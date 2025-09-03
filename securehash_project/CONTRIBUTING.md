# Contributing to Collatz-SHA1 Project

Thank you for your interest in contributing to the Collatz-SHA1 Composite Hash System!

## Development Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/yourusername/securehash_project.git
cd securehash_project
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -r requirements.txt
```

## Code Style

- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Include docstrings for all modules, classes, and functions
- Keep line length to 88 characters (Black formatter standard)

## Testing

- Add tests for all new functionality
- Ensure all tests pass before submitting:
```bash
pytest
```
- Include both unit tests and integration tests where appropriate
- Test edge cases and error conditions

## Pull Request Process

1. Create a new branch for your feature:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and commit them:
```bash
git add .
git commit -m "Description of your changes"
```

3. Update documentation as needed:
- README.md for user-facing changes
- Docstrings for API changes
- Comments for complex implementations

4. Run the test suite and ensure all tests pass

5. Push your changes and create a pull request:
```bash
git push origin feature/your-feature-name
```

6. Fill out the pull request template with:
- Description of changes
- Related issue numbers
- Testing performed
- Screenshots (if applicable)

## Code Review Process

- All submissions require review
- Reviewers will check for:
  - Correctness
  - Test coverage
  - Code style
  - Documentation
- Address review comments and push additional commits

## Security Considerations

- Do not commit sensitive information
- Report security vulnerabilities privately
- Consider cryptographic implications of changes
- Document security assumptions

## Questions?

Feel free to open an issue for:
- Feature discussions
- Bug reports
- Usage questions
- Development questions
