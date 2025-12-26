# SecurityScan - Setup Guide for Reviewers

This guide will help you set up and run SecurityScan for code review or testing purposes.

## 📋 Prerequisites

### Required
- **Python 3.8+** (Python 3.11+ recommended)
- **pip** (Python package manager)

### Optional (for full functionality)
- **WPScan** - For WordPress vulnerability scanning
- **Nuclei** - For vulnerability detection
- **Nmap** - For network scanning

**Note:** The tool will work without these external scanners, but some features will be limited.

---

## 🚀 Quick Setup (5 minutes)

### Step 1: Clone/Download the Repository

```bash
# If using git
git clone <repository-url>
cd SecurityScan

# Or extract the zip file and navigate to the directory
cd SecurityScan
```

### Step 2: Install Python Dependencies

```bash
# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Verify Installation

```bash
# Test basic functionality
python3 cli.py --help

# Should show usage information
```

---

## 📦 Optional: Install External Scanners

The tool works without these, but installing them enables more comprehensive scanning.

### WPScan (WordPress scanning)

**macOS:**
```bash
brew install wpscan
```

**Linux (Ruby gem):**
```bash
gem install wpscan
```

**Verify:**
```bash
wpscan --version
```

### Nuclei (Vulnerability detection)

**Install Go first:**
```bash
# macOS
brew install go

# Linux - Download from https://go.dev/dl/
```

**Install Nuclei:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Add to PATH:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH=$PATH:$(go env GOPATH)/bin

# Then reload
source ~/.bashrc  # or source ~/.zshrc
```

**Verify:**
```bash
nuclei -version
```

### Nmap (Network scanning)

**macOS:**
```bash
brew install nmap
```

**Linux:**
```bash
# Debian/Ubuntu
sudo apt-get install nmap

# RHEL/CentOS
sudo yum install nmap
```

**Verify:**
```bash
nmap --version
```

---

## 🎯 Basic Usage

### Run a Simple Scan

```bash
# Defensive mode (default, safe for production)
python3 cli.py https://example.com

# With output file
python3 cli.py https://example.com --output report.md

# Verbose output
python3 cli.py https://example.com --verbose
```

### Web UI (Optional)

```bash
# Start the web interface
python3 web_app.py

# Or use the startup script
./START_WEB_UI.sh

# Access at http://localhost:5000
```

---

## 🔐 Security Notes for Reviewers

### API Keys and Secrets

**This codebase does NOT contain any hardcoded API keys or secrets.**

All sensitive configuration uses environment variables:
- `WPSCAN_API_TOKEN` - Optional, for enhanced WordPress scanning
- `OPENAI_API_KEY` - Optional, for AI analysis
- `GEMINI_API_KEY` - Optional, for AI analysis
- `RESEND_API_KEY` - Optional, for email notifications

**These are NOT required for basic functionality.**

### What's Safe to Review

✅ **Safe to review:**
- All Python source code
- Configuration files (`.yaml`, `.py`)
- Documentation files (`.md`)
- Test files
- Templates and static assets

⚠️ **Excluded from git (via .gitignore):**
- `.env` files
- `*.db` database files (if any local data exists)
- `*.log` files
- API keys and secrets
- Scan result files

---

## 📁 Project Structure

```
SecurityScan/
├── cli.py                 # Command-line interface
├── web_app.py            # Web UI (Flask app)
├── src/
│   ├── scanners/         # Security scanner modules
│   ├── models/           # Data models
│   ├── parsers/          # Scanner output parsers
│   ├── reports/          # Report generators
│   └── utils/            # Utility functions
├── templates/            # Web UI templates
├── static/               # Static assets (CSS, JS)
├── requirements.txt      # Python dependencies
└── README.md            # Main documentation
```

---

## 🧪 Testing

### Run Tests

```bash
# Run all tests
python3 -m pytest  # If pytest is installed

# Or run individual test files
python3 test_scanner_functionality.py
python3 test_robustness.py
```

### Test with Sample Target

```bash
# Test on a safe target (your own site or test site)
python3 cli.py https://httpbin.org

# Or use the example script
python3 example.py
```

---

## 🔧 Configuration

### Environment Variables (Optional)

Create a `.env` file (NOT committed to git) for optional features:

```bash
# Optional: WPScan API token (enhanced WordPress scanning)
WPSCAN_API_TOKEN=your_token_here

# Optional: AI analysis
OPENAI_API_KEY=your_key_here
# OR
GEMINI_API_KEY=your_key_here

# Optional: Email notifications
RESEND_API_KEY=your_key_here
FROM_EMAIL=noreply@yourdomain.com

# Optional: OPSEC features
OPSEC_ENABLED=true
OPSEC_ROTATE_USER_AGENT=true
```

**Note:** None of these are required. The tool works fully without them.

---

## 📚 Documentation

Additional documentation files:
- `README.md` - Main documentation
- `INSTALLATION.md` - Detailed installation guide
- `FEATURES_AND_CAPABILITIES.md` - Feature overview
- `OFFENSIVE_MODE.md` - Information about offensive mode
- `WEB_UI_QUICKSTART.md` - Web UI setup guide

---

## ❓ Troubleshooting

### Scanner Not Found

```bash
# Check if scanner is installed
which wpscan
which nuclei
which nmap

# If nuclei not found, add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### Import Errors

```bash
# Make sure dependencies are installed
pip install -r requirements.txt

# If in virtual environment, make sure it's activated
source venv/bin/activate  # or venv\Scripts\activate on Windows
```

### Permission Errors

```bash
# Some scanners may need permissions (rare)
# Check file permissions
ls -la cli.py
chmod +x cli.py  # If needed
```

---

## 🎓 For Code Reviewers

### Key Files to Review

**Core Logic:**
- `src/orchestrator.py` - Main scan orchestration
- `src/scanners/*.py` - Individual scanner implementations
- `src/models/*.py` - Data models

**Recent Improvements:**
- `src/scanners/api_security.py` - API endpoint detection
- `src/scanners/ssrf_scanner.py` - SSRF detection
- `src/scanners/xxe_scanner.py` - XXE detection
- `src/scanners/wordpress_analyzer.py` - WordPress analysis

**False Positive Fixes:**
- `FALSE_POSITIVE_IMPROVEMENTS.md` - Recent improvements
- `404_429_FILTERING_FIXES.md` - Status code filtering

### Code Quality

- Type hints used throughout
- Comprehensive error handling
- Logging for debugging
- Unit tests available
- Documentation strings

---

## 🚨 Important Notes

1. **No Hardcoded Secrets**: All API keys use environment variables
2. **Safe by Default**: Runs in defensive mode by default
3. **Offensive Mode**: Requires explicit `--offensive` flag
4. **Respect Rate Limits**: Tool includes rate limiting and respectful scanning
5. **Production Safe**: Defensive mode is safe for production environments

---

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review `INSTALLATION.md` for detailed setup
3. Check scanner-specific installation guides
4. Verify all prerequisites are installed

---

## ✅ Verification Checklist

Before reviewing, verify:

- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Can run `python3 cli.py --help`
- [ ] Optional: External scanners installed (WPScan, Nuclei, Nmap)
- [ ] Can run a test scan on a safe target
- [ ] No `.env` files in repository (good - using .gitignore)
- [ ] No hardcoded API keys in source code

---

**Happy reviewing!** 🎉

