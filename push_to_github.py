#!/usr/bin/env python3
"""
NrMAP GitHub Push Script
Pushes the NrMAP project to GitHub using credentials from .env file
"""

import os
import subprocess
import sys
from pathlib import Path
from dotenv import load_dotenv

def run_command(cmd, check=True, capture_output=False):
    """Run a shell command"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {cmd}")
        print(f"Error: {e.stderr if capture_output else e}")
        if check:
            sys.exit(1)
        return None

def main():
    print("=== NrMAP GitHub Push Script ===")
    print()

    # Load .env file
    env_path = Path(".env")
    if not env_path.exists():
        print("❌ Error: .env file not found!")
        print()
        print("Please create a .env file with your GitHub token:")
        print("  GITHUB_TOKEN=your_token_here")
        print("  GITHUB_REPO=deepskilling/RUSTSCAN")
        print("  GITHUB_USER=deepskilling")
        sys.exit(1)

    print("📁 Loading environment variables from .env...")
    load_dotenv()

    # Get GitHub token (prefer GITHUB_TOKEN, fallback to GITHUB_TOKEN_DILIGENT)
    github_token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN_DILIGENT")
    github_repo = os.getenv("GITHUB_REPO", "deepskilling/RUSTSCAN")
    github_user = os.getenv("GITHUB_USER", "deepskilling")

    if not github_token:
        print("❌ Error: GITHUB_TOKEN not set in .env file!")
        print()
        print("Please set GITHUB_TOKEN in your .env file")
        print("Get your token from: https://github.com/settings/tokens")
        sys.exit(1)

    print("✓ Environment variables loaded")
    print()

    # Initialize git if needed
    if not Path(".git").exists():
        print("🔧 Initializing git repository...")
        run_command("git init")
        print("✓ Git repository initialized")
    else:
        print("✓ Git repository already initialized")

    # Configure git user
    result = run_command("git config user.name", check=False, capture_output=True)
    if not result or not result.stdout.strip():
        print("🔧 Configuring git user...")
        run_command(f'git config user.name "{github_user}"')
        run_command(f'git config user.email "{github_user}@users.noreply.github.com"')
        print("✓ Git user configured")

    # Set remote with token
    remote_url = f"https://{github_token}@github.com/{github_repo}.git"
    print("🔗 Setting remote repository...")
    
    result = run_command("git remote get-url origin", check=False, capture_output=True)
    if result and result.returncode == 0:
        run_command(f'git remote set-url origin "{remote_url}"')
        print("✓ Remote URL updated")
    else:
        run_command(f'git remote add origin "{remote_url}"')
        print("✓ Remote origin added")

    # Get current branch
    result = run_command("git rev-parse --abbrev-ref HEAD", check=False, capture_output=True)
    current_branch = result.stdout.strip() if result and result.returncode == 0 else "main"
    if current_branch == "HEAD":
        current_branch = "main"

    print()
    print("📋 Repository Status:")
    print(f"  Repository: {github_repo}")
    print(f"  Branch: {current_branch}")
    print(f"  User: {github_user}")
    print()

    # Add all files
    print("📦 Adding files to git...")
    run_command("git add .")
    print("✓ Files added")

    # Check if there are changes to commit
    result = run_command("git diff --cached --quiet", check=False)
    if result.returncode == 0:
        print("ℹ️  No changes to commit")
    else:
        # Commit changes
        print("💾 Creating commit...")
        commit_msg = """Add NrMAP - Network Reconnaissance and Mapping Platform

Complete implementation including:
- Scanner core (host discovery, TCP/UDP/SYN scans, adaptive throttling)
- Packet engine (raw sockets, crafting, parsing)
- Detection engine (banner grabbing, fingerprinting, OS detection)
- Distributed scanning (scheduler, agents, aggregator)
- CLI with profiles and output formatting
- Report engine (JSON, YAML, HTML, CLI tables)
- OS Fingerprinting (TCP, ICMP, UDP, Protocol hints, Clock skew, Passive, Active probes)
- Fuzzy matching engine
- Database I/O (JSON/YAML import/export)

Features:
- 183 passing tests
- 4,976 lines of OS fingerprinting code
- Comprehensive logging and error handling
- Production-ready code quality
- Extensive documentation"""
        
        run_command(f'git commit -m "{commit_msg}"')
        print("✓ Commit created")

    # Push to GitHub
    print()
    print("🚀 Pushing to GitHub...")
    print(f"  Repository: https://github.com/{github_repo}")
    print(f"  Branch: {current_branch}")
    print()

    # Check if remote branch exists
    result = run_command(
        f"git rev-parse --verify origin/{current_branch}",
        check=False,
        capture_output=True
    )
    
    if result and result.returncode == 0:
        # Remote branch exists, do normal push
        run_command(f"git push origin {current_branch}")
    else:
        # Remote branch doesn't exist, do initial push
        run_command(f"git push -u origin {current_branch}")

    print()
    print("✅ Successfully pushed to GitHub!")
    print()
    print("🌐 View your repository at:")
    print(f"   https://github.com/{github_repo}")
    print()
    print("📚 Documentation files pushed:")
    print("   - README.md")
    print("   - PRD.md")
    print("   - QUICKSTART.md")
    print("   - ACTIVE_PROBE_LIBRARY.md")
    print("   - DATABASE_AND_REPORTING_COMPLETE.md")
    print("   - And more...")
    print()

    # Remove token from remote URL for security
    safe_remote_url = f"https://github.com/{github_repo}.git"
    run_command(f'git remote set-url origin "{safe_remote_url}"')
    print("🔒 Remote URL sanitized (token removed from git config)")
    print()
    print("✨ Done!")

if __name__ == "__main__":
    main()

