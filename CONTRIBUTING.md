# Contributing to NrMAP

First off, thank you for considering contributing to NrMAP! It's people like you that make NrMAP such a great tool.

## 🎯 Ways to Contribute

### 1. Reporting Bugs 🐛

Before creating bug reports, please check existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (code snippets, command outputs)
- **Describe the behavior you observed** and what you expected
- **Include your environment details** (OS, Rust version, Python version)

**Bug Report Template:**
```markdown
**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.75.0]
- Python version: [e.g., 3.11.0]
- NrMAP version: [e.g., 0.1.0]

**Description:**
A clear and concise description of the bug.

**Steps to Reproduce:**
1. Run command '...'
2. See error

**Expected Behavior:**
What you expected to happen.

**Actual Behavior:**
What actually happened.

**Logs/Screenshots:**
Any relevant logs or screenshots.
```

### 2. Suggesting Enhancements 💡

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List similar features** in other tools if applicable

### 3. Pull Requests 🔄

We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`
2. If you've added code, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

---

## 🏗️ Development Setup

### Prerequisites

- **Rust** 1.70+ ([Install Rust](https://rustup.rs/))
- **Python** 3.8+ (for Python bindings)
- **Git**

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/RUSTSCAN.git
cd RUSTSCAN

# Add upstream remote
git remote add upstream https://github.com/deepskilling/RUSTSCAN.git

# Create a branch
git checkout -b feature/my-awesome-feature

# Install dependencies
cargo build

# Run tests
cargo test
```

### Python Development

```bash
# Install development dependencies
pip install maturin pytest pytest-asyncio black mypy

# Build Python bindings
maturin develop

# Run Python tests
pytest python/tests/
```

---

## 📝 Coding Standards

### Rust Code Style

We follow the official Rust style guidelines:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Fix common issues
cargo fix
```

**Guidelines:**
- Use `rustfmt` for formatting (enforced by CI)
- Follow `clippy` recommendations
- Write meaningful variable names
- Add doc comments for public APIs
- Keep functions focused and testable

**Example:**
```rust
/// Performs a TCP connect scan on the specified port.
///
/// # Arguments
/// * `target` - The IP address to scan
/// * `port` - The port number to scan
///
/// # Returns
/// * `Ok(PortStatus)` - The status of the port
/// * `Err(ScanError)` - If the scan fails
///
/// # Examples
/// ```
/// let status = tcp_connect("192.168.1.1".parse()?, 80).await?;
/// ```
pub async fn tcp_connect(target: IpAddr, port: u16) -> ScanResult<PortStatus> {
    // Implementation
}
```

### Python Code Style

We use `black` for formatting and `mypy` for type checking:

```bash
# Format code
black python/

# Type checking
mypy python/

# Run linter
pylint python/nrmap/
```

**Guidelines:**
- Follow PEP 8
- Use type hints
- Write docstrings (Google style)
- Keep functions focused

**Example:**
```python
async def scan_ports(
    target: str,
    ports: list[int],
    scan_type: str = "tcp_connect"
) -> list[int]:
    """Scan specified ports on a target host.
    
    Args:
        target: IP address or hostname to scan
        ports: List of port numbers to scan
        scan_type: Type of scan to perform (default: "tcp_connect")
    
    Returns:
        List of open port numbers
    
    Raises:
        ValueError: If target is invalid
        ScanError: If scan fails
        
    Example:
        >>> open_ports = await scan_ports("192.168.1.1", [22, 80, 443])
        >>> print(f"Open: {open_ports}")
    """
    # Implementation
```

---

## ✅ Testing

### Writing Tests

**Rust Tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_status() {
        let status = PortStatus::Open;
        assert_eq!(status.to_string(), "Open");
    }

    #[tokio::test]
    async fn test_tcp_scan() {
        // Test implementation
    }
}
```

**Python Tests:**
```python
import pytest
from nrmap import scan_ports

@pytest.mark.asyncio
async def test_scan_localhost():
    """Test scanning localhost."""
    ports = [22, 80]
    results = await scan_ports("127.0.0.1", ports)
    assert isinstance(results, list)
```

### Running Tests

```bash
# Rust tests
cargo test

# Rust tests with output
cargo test -- --nocapture

# Single test
cargo test test_tcp_scan

# Python tests
pytest python/tests/

# Python tests with coverage
pytest --cov=nrmap python/tests/
```

---

## 📚 Documentation

### Code Documentation

- **Rust**: Use `///` for public items, `//!` for module docs
- **Python**: Use Google-style docstrings

### Updating Documentation

When you change APIs:
1. Update inline documentation
2. Update README.md if needed
3. Update examples if affected
4. Update Python documentation

---

## 🔀 Git Workflow

### Branching Strategy

- `main` - Stable, production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Critical fixes for production

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```bash
feat(scanner): add UDP scan support

fix(parser): handle malformed ICMP packets

docs(readme): update installation instructions

test(fingerprint): add OS detection tests
```

### Pull Request Process

1. **Update your branch** with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Ensure all tests pass**:
   ```bash
   cargo test
   cargo fmt -- --check
   cargo clippy
   pytest python/tests/
   ```

3. **Create a pull request** with:
   - Clear title and description
   - Reference to related issues
   - Screenshots/examples if applicable

4. **Address review feedback**
   - Make requested changes
   - Push updates to your branch
   - Request re-review

5. **Merge** (maintainers will merge approved PRs)

---

## 🏆 Recognition

Contributors are recognized in:
- GitHub contributors page
- CONTRIBUTORS.md file
- Release notes

---

## 💬 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and discussions
- **Documentation**: Check README.md and PRD.md

---

## 📜 Code of Conduct

This project adheres to a [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to NrMAP! 🙏

