"""JSON report generator."""

import json
from typing import Dict, Any

from ..models.scan import ScanResult


class JSONReporter:
    """Generate JSON reports from scan results."""
    
    @staticmethod
    def generate(scan_result: ScanResult, pretty: bool = True) -> str:
        """
        Generate JSON report.
        
        Args:
            scan_result: Scan result to report
            pretty: Whether to pretty-print JSON
            
        Returns:
            JSON string
        """
        data = scan_result.to_dict()
        
        if pretty:
            return json.dumps(data, indent=2, sort_keys=False)
        else:
            return json.dumps(data, sort_keys=False)
    
    @staticmethod
    def save(scan_result: ScanResult, filepath: str, pretty: bool = True):
        """
        Save JSON report to file.
        
        Args:
            scan_result: Scan result to report
            filepath: Output file path
            pretty: Whether to pretty-print JSON
        """
        json_str = JSONReporter.generate(scan_result, pretty=pretty)
        with open(filepath, "w") as f:
            f.write(json_str)

