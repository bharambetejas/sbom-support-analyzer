# Contributing to SBOM Support Analyzer

Thank you for considering contributing to the SBOM Support Analyzer! This document provides guidelines for contributing to the project.

## Code of Conduct

### Our Commitment

This project is dedicated to defensive security purposes only. All contributions must align with ethical security practices.

### Acceptable Contributions

✅ **Encouraged:**
- Bug fixes and improvements
- New package ecosystem support (Maven, Cargo, etc.)
- Enhanced analysis algorithms
- Documentation improvements
- Test coverage expansion
- Performance optimizations
- UI/UX improvements

❌ **Not Accepted:**
- Code for malicious purposes
- Credential harvesting features
- Exploit development tools
- Anything violating ethical guidelines

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Git
- GitHub account
- (Optional) GitHub Personal Access Token for testing

### Development Setup

1. **Fork the repository**
   ```bash
   # Click "Fork" on GitHub, then clone your fork
   git clone https://github.com/bharambetejas/sbom-support-analyzer.git
   cd sbom-support-analyzer
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

3. **Make your changes**
   - Write clear, documented code
   - Follow existing code style
   - Add comments for complex logic

4. **Test your changes**
   ```bash
   # Syntax check
   python3 -m py_compile sbom_support_analyzer.py

   # Run with test SBOM
   python3 sbom_support_analyzer.py test_sbom.json --limit 5
   ```

## Contribution Guidelines

### Code Style

- **Python:** Follow PEP 8 guidelines
- **Line length:** Max 120 characters
- **Docstrings:** Use triple quotes with clear descriptions
- **Type hints:** Use when possible
- **Comments:** Explain "why", not "what"

### Example

```python
def analyze_package(pkg_name: str, version: str) -> Dict:
    """
    Analyze package support status using registry APIs.

    Args:
        pkg_name: Package name (e.g., 'express')
        version: Version string (e.g., '4.18.0')

    Returns:
        Dict containing support level and metadata
    """
    # Query registry for release dates (needed for age calculation)
    data = fetch_registry_data(pkg_name)
    ...
```

### Commit Messages

Use clear, descriptive commit messages:

```bash
# Good
git commit -m "Add support for Cargo/Rust packages"
git commit -m "Fix PURL parsing for scoped NPM packages"
git commit -m "Update README with SPDX examples"

# Avoid
git commit -m "fix bug"
git commit -m "updates"
git commit -m "wip"
```

### Pull Request Process

1. **Update documentation** if needed
   - README.md for user-facing changes
   - STRATEGY.md for algorithm changes
   - Code comments for implementation details

2. **Test thoroughly**
   - Test with multiple SBOM formats
   - Verify backward compatibility
   - Check edge cases

3. **Create pull request**
   - Clear title describing the change
   - Detailed description of what and why
   - Reference related issues

4. **Respond to feedback**
   - Address review comments promptly
   - Be open to suggestions
   - Update PR based on feedback

## Types of Contributions

### 🐛 Bug Reports

**Before submitting:**
- Check existing issues
- Verify it's reproducible
- Test with latest version

**Include:**
- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Python version
- Sample SBOM (sanitized)
- Error messages/logs

**Template:**
```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Run command: `python3 sbom_support_analyzer.py test.json`
2. Observe error...

## Expected Behavior
Should analyze all components

## Actual Behavior
Crashes with error: ...

## Environment
- Python version: 3.9.5
- OS: Ubuntu 22.04
- SBOM format: SPDX 2.3
```

### ✨ Feature Requests

**Before requesting:**
- Check if already exists
- Verify it aligns with project goals
- Consider defensive security use only

**Include:**
- Clear use case
- Proposed solution
- Examples
- Why it's valuable

### 🔧 Code Contributions

#### Adding New Ecosystem Support

Example: Adding Cargo (Rust) support

1. **Add ecosystem method**
   ```python
   def _analyze_cargo_package(self, name: str, version: str) -> Dict:
       """Analyze Cargo/Rust package"""
       url = f"https://crates.io/api/v1/crates/{name}"
       data = self._make_request(url)
       # ... implementation
   ```

2. **Update PURL parsing**
   ```python
   elif ecosystem == 'cargo':
       package_data = self._analyze_cargo_package(pkg_name, pkg_version)
   ```

3. **Add documentation**
   - Update README ecosystem table
   - Add to STRATEGY.md
   - Include usage example

4. **Test**
   - Create test SBOM with Cargo packages
   - Verify analysis works
   - Check edge cases

#### Improving Analysis Logic

1. **Document current behavior**
2. **Explain proposed improvement**
3. **Show before/after examples**
4. **Test with various scenarios**

### 📚 Documentation

- Fix typos
- Clarify confusing sections
- Add examples
- Update outdated information
- Translate to other languages

### 🧪 Testing

- Add test cases
- Improve test coverage
- Create sample SBOMs
- Validate edge cases

## Development Best Practices

### Security

- Never commit tokens or credentials
- Sanitize SBOM examples (remove company data)
- Validate all inputs
- Handle errors gracefully
- Use HTTPS for all API calls

### Performance

- Cache API responses when possible
- Respect rate limits
- Use efficient algorithms
- Profile before optimizing

### Compatibility

- Test on multiple Python versions (3.7, 3.9, 3.11)
- Maintain backward compatibility
- Document breaking changes clearly
- Use standard library when possible

## API Guidelines

When adding new package registry support:

1. **Use public APIs only**
2. **Respect rate limits**
3. **Handle errors gracefully**
4. **Cache responses**
5. **Document API endpoints**

### Example

```python
def _analyze_new_registry(self, name: str, version: str) -> Dict:
    """
    Analyze package from NewRegistry

    API: https://api.newregistry.com/v1
    Rate limit: 100 requests/minute
    Documentation: https://docs.newregistry.com
    """
    self.request_count['newregistry'] += 1

    url = f"https://api.newregistry.com/v1/packages/{name}"
    data = self._make_request(url)

    if not data:
        return {'success': False}

    # ... parse response
```

## Review Process

1. **Automated checks**
   - Python syntax validation
   - Code style check (if configured)

2. **Manual review**
   - Code quality
   - Security considerations
   - Documentation completeness
   - Test coverage

3. **Approval**
   - Requires maintainer approval
   - May request changes
   - Merge when ready

## Getting Help

- **Questions:** Open a GitHub Discussion
- **Bugs:** Create an Issue
- **Security:** See SECURITY.md (if exists)
- **General:** Comment on related Issue/PR

## Recognition

Contributors will be:
- Listed in project credits
- Mentioned in release notes
- Acknowledged in commit history

## License

By contributing, you agree that your contributions will be licensed under the MIT License with the defensive security clause.

## Thank You!

Every contribution, no matter how small, makes this project better. We appreciate your time and effort! 🎉

---

**Questions?** Open an issue or discussion on GitHub.
