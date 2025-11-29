# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of NrMAP seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please Do Not

- **Do not** open a public GitHub issue for security vulnerabilities
- **Do not** disclose the vulnerability publicly until it has been addressed

### Please Do

1. **Report via GitHub Security Advisories**
   - Go to the [Security tab](https://github.com/deepskilling/RUSTSCAN/security)
   - Click "Report a vulnerability"
   - Fill out the form with as much detail as possible

2. **Include in Your Report:**
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
   - Your contact information (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Updates**: Every 7-14 days
- **Fix Timeline**: Varies by severity
  - Critical: 1-7 days
  - High: 7-30 days
  - Medium: 30-90 days
  - Low: 90+ days

### Security Best Practices

When using NrMAP:

#### 1. Run with Least Privilege

```bash
# Use capabilities instead of root (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/nrmap

# Then run as regular user
./target/release/nrmap scan --target 192.168.1.1
```

#### 2. Network Isolation

- Use dedicated scanning VLANs
- Implement firewall rules
- Monitor scanning traffic

#### 3. Secure Configuration

```toml
# config.toml - Recommended settings
[scanner]
max_concurrent_scans = 50  # Avoid overwhelming targets
default_timeout_ms = 2000   # Reasonable timeout

[logging]
level = "warn"              # Don't log sensitive info in production
```

#### 4. Authorized Use Only

⚠️ **Warning**: Unauthorized port scanning may be illegal in your jurisdiction.

- Only scan networks you own or have explicit permission to test
- Obtain written authorization
- Follow responsible disclosure guidelines
- Comply with local laws and regulations

#### 5. Input Validation

The tool validates inputs, but always:
- Sanitize configuration files
- Verify target lists
- Check port ranges

### Known Security Considerations

#### Raw Socket Requirements

NrMAP requires elevated privileges for:
- TCP SYN scanning
- ICMP operations
- Raw packet manipulation

**Mitigation:**
- Use Linux capabilities instead of full root
- Run in isolated environments
- Audit access logs

#### Network Impact

High-speed scanning can:
- Trigger IDS/IPS alerts
- Cause network congestion
- Crash vulnerable systems

**Mitigation:**
- Use adaptive throttling (enabled by default)
- Start with conservative scan rates
- Monitor target systems

#### Information Disclosure

Scanning reveals:
- Open ports and services
- Operating system details
- Network topology

**Mitigation:**
- Encrypt reports
- Secure storage of results
- Limit access to scan data

### Security Updates

Subscribe to security advisories:
- Watch the repository on GitHub
- Enable security alerts
- Follow release notes

### Vulnerability Disclosure Process

1. **Report Received**: We acknowledge receipt
2. **Validation**: We validate and assess severity
3. **Fix Development**: We develop and test a fix
4. **Coordinated Disclosure**: We prepare advisory
5. **Release**: We release patched version
6. **Public Disclosure**: We publish security advisory

### Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

*No vulnerabilities reported yet. Be the first!*

---

## Security Checklist for Developers

If you're contributing code:

- [ ] Input validation on all external data
- [ ] No hardcoded credentials or secrets
- [ ] Secure defaults in configuration
- [ ] Error messages don't leak sensitive info
- [ ] Dependencies are up to date
- [ ] Code follows secure coding guidelines
- [ ] Tests include security test cases
- [ ] Documentation includes security considerations

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Working Group](https://www.rust-lang.org/governance/wgs/wg-security-response)
- [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/)

---

Thank you for helping keep NrMAP and its users safe! 🔐

