#!/bin/bash
# IoC-Hunter Linux Setup Script
# Supports Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2
# Estimated time: 30-60 seconds

set -e  # Exit on any error

echo "================================================================"
echo "             IoC-Hunter Linux Setup"
echo "================================================================"
echo "Target Systems: Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2"
echo "Python Target: 3.9+ compatibility"
echo "================================================================"

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    warning "Running as root. This is acceptable but not required for setup."
fi

# Detect distribution
info "Detecting Linux distribution..."
if command -v lsb_release &> /dev/null; then
    DISTRO=$(lsb_release -si 2>/dev/null)
    VERSION=$(lsb_release -sr 2>/dev/null)
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$NAME
    VERSION=$VERSION_ID
else
    error "Cannot detect Linux distribution"
    exit 1
fi

info "Detected: $DISTRO $VERSION"

# Validate supported distributions
case "$DISTRO" in
    "Ubuntu")
        if [[ "$VERSION" < "24.04" ]]; then
            warning "Ubuntu version $VERSION detected. Tested on 24.04.3+"
        fi
        PACKAGE_MANAGER="apt"
        ;;
    "Fedora"|"Fedora Linux")
        if [[ "$VERSION" < "42" ]]; then
            warning "Fedora version $VERSION detected. Tested on 42+"
        fi
        PACKAGE_MANAGER="dnf"
        ;;
    *"Oracle Linux"*|*"Red Hat"*|*"CentOS"*|*"AlmaLinux"*|*"Rocky Linux"*)
        if [[ "$VERSION" < "9" ]]; then
            warning "RHEL-based version $VERSION detected. Tested on Oracle Linux 9.2+"
        fi
        PACKAGE_MANAGER="yum"
        ;;
    *)
        warning "Unsupported distribution: $DISTRO. Attempting generic setup..."
        # Try to detect package manager
        if command -v apt &> /dev/null; then
            PACKAGE_MANAGER="apt"
        elif command -v dnf &> /dev/null; then
            PACKAGE_MANAGER="dnf"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        else
            error "No supported package manager found (apt, dnf, yum)"
            exit 1
        fi
        ;;
esac

info "Using package manager: $PACKAGE_MANAGER"

# Check Python version
info "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    info "Found Python $PYTHON_VERSION"
    
    # Check if version is 3.9+
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
        success "Python $PYTHON_VERSION is compatible (3.9+ required)"
    else
        error "Python $PYTHON_VERSION is too old. Python 3.9+ required."
        exit 1
    fi
else
    error "Python 3 not found. Please install Python 3.9+ first."
    exit 1
fi

# Install system packages
info "Installing system packages..."
case "$PACKAGE_MANAGER" in
    "apt")
        info "Updating package list..."
        sudo apt update -qq
        
        info "Installing required packages..."
        sudo apt install -y \
            python3-pip \
            python3-dev \
            python3-systemd \
            jq \
            curl \
            grep \
            gawk \
            sed
        ;;
    "dnf")
        info "Installing required packages..."
        sudo dnf install -y \
            python3-pip \
            python3-devel \
            python3-systemd \
            jq \
            curl \
            grep \
            gawk \
            sed
        ;;
    "yum")
        info "Installing required packages..."
        sudo yum install -y \
            python3-pip \
            python3-devel \
            jq \
            curl \
            grep \
            gawk \
            sed
        
        # python3-systemd might not be available on older RHEL-based systems
        if ! sudo yum install -y python3-systemd 2>/dev/null; then
            warning "python3-systemd not available via system packages. Will install via pip."
        fi
        ;;
esac

# Check pip availability
info "Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    error "pip3 not found after package installation"
    exit 1
fi

# Install Python packages
info "Installing Python packages..."
pip3 install --user -r requirements.txt

# Verify critical imports
info "Verifying Python package installation..."
python3 -c "
try:
    import json, subprocess, datetime, pathlib, re, logging, argparse
    import concurrent.futures, gzip, bz2, glob, sys, os
    from typing import Union, Optional, List, Dict, Any
    print('✓ Standard library imports successful')
    
    try:
        from dateutil.parser import parse
        from dateutil.relativedelta import relativedelta
        print('✓ dateutil import successful')
    except ImportError as e:
        print(f'✗ dateutil import failed: {e}')
        sys.exit(1)
    
    try:
        import systemd.journal
        print('✓ systemd import successful')
    except ImportError as e:
        print(f'✗ systemd import failed: {e}')
        print('Will attempt to use journalctl via subprocess')
    
    try:
        import splunklib.client
        print('✓ splunk-sdk import successful')
    except ImportError as e:
        print(f'✗ splunk-sdk import failed: {e}')
        print('Splunk integration will be unavailable')

except Exception as e:
    print(f'✗ Critical import failed: {e}')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    error "Python package verification failed"
    exit 1
fi

# Make CLI script executable
info "Setting up CLI script..."
chmod +x scripts/ioc-hunter

# Create symlink for system-wide access (optional)
if [[ $EUID -eq 0 ]] || sudo -n true 2>/dev/null; then
    info "Creating system-wide symlink..."
    sudo ln -sf "$(pwd)/scripts/ioc-hunter" /usr/local/bin/ioc-hunter 2>/dev/null || true
fi

# Verify access to key log sources
info "Verifying log source access..."
LOG_ACCESS_OK=true

# Check journald access
if command -v journalctl &> /dev/null; then
    if journalctl --lines=1 &> /dev/null; then
        success "journalctl access verified"
    else
        warning "journalctl requires elevated privileges for full access"
    fi
else
    warning "journalctl not found"
    LOG_ACCESS_OK=false
fi

# Check auth.log access
AUTH_LOG="/var/log/auth.log"
if [ -f "$AUTH_LOG" ]; then
    if [ -r "$AUTH_LOG" ]; then
        success "auth.log access verified"
    else
        warning "auth.log requires elevated privileges for access"
    fi
else
    info "auth.log not found (normal on some systems)"
fi

# Final setup verification
info "Running setup verification..."
if python3 -c "
import sys
sys.path.insert(0, '.')
from ioc_hunter.core.scanner import IoCScanner
scanner = IoCScanner()
print('✓ IoC-Hunter framework initialization successful')
"; then
    success "Framework verification passed"
else
    error "Framework verification failed"
    exit 1
fi

echo ""
echo "================================================================"
success "IoC-Hunter Linux setup completed successfully!"
echo "================================================================"
echo ""
echo "Quick Start:"
echo "  # Quick scan (requires root for full functionality)"
echo "  sudo ./scripts/ioc-hunter --quick"
echo ""
echo "  # Or use system-wide command (if symlink created)"
echo "  sudo ioc-hunter --quick"
echo ""
echo "  # Help and available options"
echo "  ./scripts/ioc-hunter --help"
echo ""
echo "Documentation:"
echo "  README.md           - Overview and examples"
echo "  docs/USAGE_GUIDE.md - Comprehensive usage guide"
echo "  docs/BLUE_TEAM_GUIDE.md - Blue team specific guidance"
echo ""
echo "Important Notes:"
echo "  - Root privileges required for comprehensive log access"
echo "  - Default scan window: 20 minutes"
echo "  - Tested on Ubuntu 24.04.3, Fedora 42, Oracle Linux 9.2"
echo ""
echo "================================================================"
