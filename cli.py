#!/usr/bin/env python3
"""CLI interface for SecurityScan."""

import argparse
import logging
import sys
from pathlib import Path

from src.orchestrator import ScanOrchestrator
from src.reports.json_reporter import JSONReporter
from src.reports.markdown_reporter import MarkdownReporter
from src.models.scan_mode import ScanMode


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Defensive security reconnaissance and risk-scoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python cli.py https://example.com

  # Scan with JSON output
  python cli.py https://example.com --output report.json --format json

  # Scan with Markdown output
  python cli.py https://example.com --output report.md --format markdown

  # Disable specific scanners
  python cli.py https://example.com --no-wpscan --no-nmap

  # Verbose output
  python cli.py https://example.com --verbose
        """,
    )
    
    parser.add_argument(
        "target",
        help="Target URL or domain to scan",
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)",
        default=None,
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["json", "markdown", "both"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    
    parser.add_argument(
        "--no-wpscan",
        action="store_true",
        help="Disable WPScan scanner",
    )
    
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="Disable Nuclei scanner",
    )
    
    parser.add_argument(
        "--no-nmap",
        action="store_true",
        help="Disable Nmap scanner",
    )
    
    parser.add_argument(
        "--wpscan-api-token",
        help="WPScan API token (or set WPSCAN_API_TOKEN env var)",
        default=None,
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    parser.add_argument(
        "--offensive",
        action="store_true",
        help="Enable offensive/exploitation mode (WARNING: Will attempt to exploit vulnerabilities)",
    )
    
    parser.add_argument(
        "--enable-sqlmap",
        action="store_true",
        help="Enable SQLMap scanner (offensive mode only, requires --offensive)",
    )
    
    parser.add_argument(
        "--skip-warning",
        action="store_true",
        help="Skip offensive mode warning (use with caution)",
    )
    
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast scan mode (reduced timeouts, fewer checks)",
    )
    
    args = parser.parse_args()
    
    # Validate offensive mode usage
    if args.offensive and not args.skip_warning:
        print("\n" + "=" * 70)
        print("⚠️  WARNING: OFFENSIVE MODE ENABLED ⚠️")
        print("=" * 70)
        print("This mode will attempt to EXPLOIT vulnerabilities.")
        print("ONLY use on systems you own or have explicit authorization to test.")
        print("Unauthorized use may be ILLEGAL and UNETHICAL.")
        print("=" * 70)
        response = input("\nDo you have authorization to test this target? (yes/no): ")
        if response.lower() not in ["yes", "y"]:
            print("Aborting scan. Use --skip-warning to bypass this check (not recommended).")
            sys.exit(1)
        print()
    
    if args.enable_sqlmap and not args.offensive:
        logger.error("--enable-sqlmap requires --offensive mode")
        sys.exit(1)
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Validate target input
        if not args.target or not args.target.strip():
            logger.error("Target URL or domain is required")
            sys.exit(1)
        
        target = args.target.strip()
        
        # Basic URL validation
        if not (target.startswith("http://") or target.startswith("https://") or 
                "." in target or target.replace(".", "").replace("-", "").isalnum()):
            logger.warning(f"Target '{target}' may not be a valid URL or domain. Proceeding anyway...")
        
        # Check PATH for Go bin (needed for Nuclei)
        import os
        import shutil
        go_bin = shutil.which("go")
        if go_bin and not args.no_nuclei:
            go_path = os.path.join(os.path.dirname(go_bin), "..", "bin")
            # Try to add Go bin to PATH if not already there
            go_bin_path = os.path.expanduser("~/go/bin")
            if os.path.exists(go_bin_path) and go_bin_path not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{go_bin_path}:{os.environ.get('PATH', '')}"
                logger.debug(f"Added {go_bin_path} to PATH for Nuclei")
        
        # Determine scan mode
        scan_mode = ScanMode.OFFENSIVE if args.offensive else ScanMode.DEFENSIVE
        
        # Initialize orchestrator
        try:
            orchestrator = ScanOrchestrator(
                enable_wpscan=not args.no_wpscan,
                enable_nuclei=not args.no_nuclei,
                enable_nmap=not args.no_nmap,
                enable_sqlmap=args.enable_sqlmap,
                wpscan_api_token=args.wpscan_api_token,
                scan_mode=scan_mode,
            )
        except RuntimeError as e:
            logger.error(f"Failed to initialize scanners: {e}")
            sys.exit(1)
        
        # Run scan
        logger.info(f"Starting security scan of {target}")
        result = orchestrator.scan(target)
        
        # Generate reports
        try:
            if args.format in ["json", "both"]:
                json_output = JSONReporter.generate(result, pretty=True)
                if args.output and args.format == "json":
                    output_path = Path(args.output)
                    # Create parent directory if it doesn't exist
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    JSONReporter.save(result, str(output_path))
                    logger.info(f"JSON report saved to {output_path}")
                else:
                    print(json_output)
            
            if args.format in ["markdown", "both"]:
                markdown_output = MarkdownReporter.generate(result)
                if args.output:
                    if args.format == "both":
                        # Save markdown to .md file, JSON to .json file
                        output_path = Path(args.output)
                        md_path = output_path.with_suffix(".md")
                        json_path = output_path.with_suffix(".json")
                        # Create parent directory if it doesn't exist
                        md_path.parent.mkdir(parents=True, exist_ok=True)
                        json_path.parent.mkdir(parents=True, exist_ok=True)
                        MarkdownReporter.save(result, str(md_path))
                        JSONReporter.save(result, str(json_path))
                        logger.info(f"Markdown report saved to {md_path}")
                        logger.info(f"JSON report saved to {json_path}")
                    else:
                        output_path = Path(args.output)
                        # Create parent directory if it doesn't exist
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        MarkdownReporter.save(result, str(output_path))
                        logger.info(f"Markdown report saved to {output_path}")
                else:
                    print(markdown_output)
        except Exception as e:
            logger.error(f"Failed to generate report: {e}", exc_info=args.verbose)
            # Still try to show basic results
            print(f"\nScan completed with {len(result.findings)} finding(s)")
            if result.risk_score:
                print(f"Risk score: {result.risk_score.overall_score}/100 ({result.risk_score.risk_level.value})")
            raise
        
        # Exit with appropriate code
        if result.risk_score and result.risk_score.risk_level.value in ["critical", "high"]:
            sys.exit(1)  # Exit with error for high-risk findings
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()

