#!/usr/bin/env python3
"""Example usage of DarkOrca programmatically."""

import logging
from src.orchestrator import ScanOrchestrator
from src.reports.json_reporter import JSONReporter
from src.reports.markdown_reporter import MarkdownReporter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

def main():
    """Example: Run a scan programmatically."""
    
    # Initialize orchestrator
    # You can enable/disable specific scanners
    orchestrator = ScanOrchestrator(
        enable_wpscan=True,
        enable_nuclei=True,
        enable_nmap=True,
        wpscan_api_token=None,  # Or set via env var: WPSCAN_API_TOKEN
    )
    
    # Run scan
    target_url = "https://example.com"  # Replace with your target
    print(f"Scanning {target_url}...")
    
    result = orchestrator.scan(target_url)
    
    # Print summary
    print(f"\nScan completed!")
    print(f"Total findings: {len(result.findings)}")
    if result.risk_score:
        print(f"Risk score: {result.risk_score.overall_score}/100")
        print(f"Risk level: {result.risk_score.risk_level.value}")
        print(f"\nSummary: {result.risk_score.summary}")
    
    # Generate reports
    print("\n" + "="*50)
    print("Markdown Report:")
    print("="*50)
    markdown = MarkdownReporter.generate(result)
    print(markdown)
    
    # Save to files
    JSONReporter.save(result, "example_report.json")
    MarkdownReporter.save(result, "example_report.md")
    print("\nReports saved to example_report.json and example_report.md")

if __name__ == "__main__":
    main()

