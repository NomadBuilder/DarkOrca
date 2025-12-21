#!/usr/bin/env python3
"""Test script for DarkOrca tool."""

import sys
import os
import subprocess
from pathlib import Path

# Add Go bin to PATH
go_bin = os.path.expanduser("~/go/bin")
if os.path.exists(go_bin):
    os.environ["PATH"] = f"{go_bin}:{os.environ.get('PATH', '')}"

def test_imports():
    """Test that all imports work."""
    print("Testing imports...")
    try:
        from src.orchestrator import ScanOrchestrator
        from src.models.scan import ScanTarget, ScanResult
        from src.models.finding import Finding, FindingSeverity, FindingCategory
        from src.reports.json_reporter import JSONReporter
        from src.reports.markdown_reporter import MarkdownReporter
        print("✅ All imports successful")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_scan_target_validation():
    """Test ScanTarget validation."""
    print("\nTesting ScanTarget validation...")
    from src.models.scan import ScanTarget
    
    test_cases = [
        ("https://example.com", True),
        ("http://example.com", True),
        ("example.com", True),  # Should add https://
        ("invalid-url", True),  # Will be converted to https://invalid-url (scanners will handle if invalid)
        ("", False),  # Should fail
        ("ftp://example.com", False),  # Unsupported scheme
    ]
    
    passed = 0
    for url, should_pass in test_cases:
        try:
            target = ScanTarget(url=url)
            if should_pass:
                print(f"  ✅ '{url}' -> {target.url} (domain: {target.domain})")
                passed += 1
            else:
                print(f"  ❌ '{url}' should have failed but didn't")
        except Exception as e:
            if not should_pass:
                print(f"  ✅ '{url}' correctly rejected: {e}")
                passed += 1
            else:
                print(f"  ❌ '{url}' should have passed but failed: {e}")
    
    print(f"  Result: {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)

def test_scanner_availability():
    """Test scanner availability checks."""
    print("\nTesting scanner availability...")
    from src.scanners.wpscan import WPScanAdapter
    from src.scanners.nuclei import NucleiAdapter
    from src.scanners.nmap import NmapAdapter
    
    scanners = [
        ("WPScan", WPScanAdapter),
        ("Nuclei", NucleiAdapter),
        ("Nmap", NmapAdapter),
    ]
    
    for name, adapter_class in scanners:
        try:
            adapter = adapter_class(enabled=True)
            available = adapter.is_available()
            status = "✅" if available else "⚠️"
            print(f"  {status} {name}: {'Available' if available else 'Not available'}")
        except Exception as e:
            print(f"  ❌ {name}: Error checking availability - {e}")
    
    return True

def test_orchestrator_init():
    """Test orchestrator initialization."""
    print("\nTesting orchestrator initialization...")
    from src.orchestrator import ScanOrchestrator
    
    try:
        # Test with all scanners
        orchestrator = ScanOrchestrator(
            enable_wpscan=True,
            enable_nuclei=True,
            enable_nmap=True,
        )
        print(f"  ✅ Orchestrator initialized with {len(orchestrator.scanners)} scanner(s)")
        
        # Test with some disabled
        orchestrator2 = ScanOrchestrator(
            enable_wpscan=False,
            enable_nuclei=True,
            enable_nmap=False,
        )
        print(f"  ✅ Orchestrator initialized with selective scanners: {len(orchestrator2.scanners)} scanner(s)")
        
        return True
    except Exception as e:
        print(f"  ❌ Orchestrator initialization failed: {e}")
        return False

def test_cli_help():
    """Test CLI help output."""
    print("\nTesting CLI help...")
    try:
        result = subprocess.run(
            [sys.executable, "cli.py", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and "target" in result.stdout:
            print("  ✅ CLI help works")
            return True
        else:
            print(f"  ❌ CLI help failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ❌ CLI help test failed: {e}")
        return False

def test_quick_scan():
    """Test a quick scan (may take a while)."""
    print("\nTesting quick scan (this may take a minute)...")
    print("  Note: This will only test with Nuclei (fastest scanner)")
    
    try:
        from src.orchestrator import ScanOrchestrator
        
        orchestrator = ScanOrchestrator(
            enable_wpscan=False,  # Skip WPScan (slow)
            enable_nuclei=True,
            enable_nmap=False,  # Skip Nmap (slow)
        )
        
        if not orchestrator.scanners:
            print("  ⚠️  No scanners available, skipping scan test")
            return True
        
        print(f"  Running scan with {len(orchestrator.scanners)} scanner(s)...")
        result = orchestrator.scan("https://example.com")
        
        print(f"  ✅ Scan completed:")
        print(f"     - Findings: {len(result.findings)}")
        print(f"     - Scanners run: {result.scanners_run}")
        if result.risk_score:
            print(f"     - Risk score: {result.risk_score.overall_score}/100")
        if result.scanner_errors:
            print(f"     - Errors: {result.scanner_errors}")
        
        return True
    except Exception as e:
        print(f"  ❌ Scan test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("DarkOrca Tool Test Suite")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("ScanTarget Validation", test_scan_target_validation),
        ("Scanner Availability", test_scanner_availability),
        ("Orchestrator Initialization", test_orchestrator_init),
        ("CLI Help", test_cli_help),
    ]
    
    # Optional: test actual scan (can be slow)
    if "--full" in sys.argv:
        tests.append(("Quick Scan", test_quick_scan))
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())

