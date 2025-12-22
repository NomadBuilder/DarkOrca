#!/usr/bin/env python3
"""Test script to run YAML deserialization scanner on a specific URL."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scanners.deserialization_scanner import DeserializationScanner
from src.models.scan import ScanTarget
from src.models.scan_mode import ScanMode
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_yaml_scanner(url: str):
    """Test YAML deserialization scanner on a specific URL."""
    print(f"\n{'='*70}")
    print(f"Testing YAML Deserialization Scanner")
    print(f"Target URL: {url}")
    print(f"{'='*70}\n")
    
    # Create scanner in offensive mode (required for deserialization tests)
    scanner = DeserializationScanner(enabled=True, scan_mode=ScanMode.OFFENSIVE)
    
    # Create scan target
    target = ScanTarget(url=url)
    
    # Run the scanner
    print("Running YAML deserialization tests...")
    print("This may take a minute as we test multiple endpoints and payloads...\n")
    
    try:
        findings = scanner.scan(target)
        
        print(f"\n{'='*70}")
        print(f"RESULTS: {len(findings)} finding(s) found")
        print(f"{'='*70}\n")
        
        if not findings:
            print("✅ No YAML deserialization vulnerabilities detected.")
            print("   This suggests the previous findings were likely false positives.")
        else:
            for i, finding in enumerate(findings, 1):
                print(f"\n{'─'*70}")
                print(f"FINDING #{i}: {finding.title}")
                print(f"{'─'*70}")
                print(f"Severity: {finding.severity.value}")
                print(f"URL: {finding.url}")
                print(f"Description: {finding.description}")
                print(f"\nEvidence:")
                print(f"  {finding.evidence}")
                
                if finding.exploitation_details:
                    print(f"\nExploitation Details:")
                    print(f"  {finding.exploitation_details}")
                
                if finding.metadata:
                    print(f"\nMetadata:")
                    for key, value in finding.metadata.items():
                        print(f"  {key}: {value}")
                
                print(f"\nRemediation:")
                print(f"  {finding.remediation}")
                
                # Special note about verification
                if finding.metadata and finding.metadata.get('verification_status') == 'unverified':
                    print(f"\n⚠️  WARNING: This finding is UNVERIFIED and requires manual review.")
                    print(f"   It may be a false positive from input reflection or template evaluation.")
                elif finding.metadata and finding.metadata.get('type') == 'yaml_verified':
                    print(f"\n✅ VERIFIED: This is a confirmed remote code execution vulnerability!")
                
        print(f"\n{'='*70}\n")
        
    except Exception as e:
        print(f"\n❌ Error running scanner: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    target_url = "https://www.rebelnews.com/"
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    
    exit_code = test_yaml_scanner(target_url)
    sys.exit(exit_code)
