"""Evidence collection utility for capturing request/response data."""

import requests
from typing import Dict, Any, Optional
import json


class EvidenceCollector:
    """Utility for collecting and formatting evidence from HTTP requests/responses."""
    
    @staticmethod
    def collect_request_response(
        response: requests.Response,
        request_url: Optional[str] = None,
        request_method: str = "GET",
        request_headers: Optional[Dict[str, str]] = None,
        request_data: Optional[Any] = None,
        max_content_length: int = 5000
    ) -> Dict[str, Any]:
        """
        Collect evidence from an HTTP request/response.
        
        Args:
            response: The response object from requests
            request_url: The request URL (if available)
            request_method: HTTP method used
            request_headers: Request headers (if available)
            request_data: Request data/body (if available)
            max_content_length: Maximum length of response content to include
        
        Returns:
            Dictionary containing evidence data
        """
        evidence = {
            'request': {
                'method': request_method,
                'url': request_url or str(response.url),
            },
            'response': {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
            }
        }
        
        # Add request headers if available
        if request_headers:
            evidence['request']['headers'] = request_headers
        elif hasattr(response, 'request') and response.request:
            if hasattr(response.request, 'headers'):
                evidence['request']['headers'] = dict(response.request.headers)
        
        # Add request data if available
        if request_data:
            if isinstance(request_data, dict):
                evidence['request']['data'] = request_data
            else:
                evidence['request']['body'] = str(request_data)[:500]  # Limit length
        
        # Add response content (truncated)
        try:
            # Try to get text content
            content_text = response.text
            if len(content_text) > max_content_length:
                evidence['response']['content'] = content_text[:max_content_length] + f"\n... (truncated, total length: {len(content_text)} bytes)"
                evidence['response']['content_preview'] = content_text[:500]
            else:
                evidence['response']['content'] = content_text
        except:
            # If text decoding fails, include raw bytes preview
            content_bytes = response.content
            if len(content_bytes) > max_content_length:
                evidence['response']['content_preview'] = content_bytes[:500].decode('utf-8', errors='ignore')
                evidence['response']['content_length'] = len(content_bytes)
            else:
                evidence['response']['content'] = content_bytes.decode('utf-8', errors='ignore')
        
        # Add timing information if available
        if hasattr(response, 'elapsed'):
            evidence['response']['elapsed_seconds'] = response.elapsed.total_seconds()
        
        return evidence
    
    @staticmethod
    def format_evidence_string(evidence_data: Dict[str, Any]) -> str:
        """
        Format evidence data as a readable string.
        
        Args:
            evidence_data: Evidence dictionary from collect_request_response
        
        Returns:
            Formatted evidence string
        """
        parts = []
        
        # Request information
        request_info = evidence_data.get('request', {})
        if request_info:
            method = request_info.get('method', 'GET')
            url = request_info.get('url', 'Unknown')
            parts.append(f"Request: {method} {url}")
        
        # Response information
        response_info = evidence_data.get('response', {})
        if response_info:
            status_code = response_info.get('status_code')
            parts.append(f"Status Code: {status_code}")
            
            # Important headers
            headers = response_info.get('headers', {})
            important_headers = ['Content-Type', 'Content-Length', 'Server', 'X-Powered-By']
            header_parts = []
            for header in important_headers:
                if header in headers:
                    header_parts.append(f"{header}: {headers[header]}")
            if header_parts:
                parts.append("Headers: " + ", ".join(header_parts))
            
            # Content preview
            content = response_info.get('content') or response_info.get('content_preview')
            if content:
                content_str = str(content)
                if len(content_str) > 500:
                    parts.append(f"Response Content (first 500 chars): {content_str[:500]}...")
                else:
                    parts.append(f"Response Content: {content_str}")
        
        return "\n".join(parts)
    
    @staticmethod
    def format_evidence_json(evidence_data: Dict[str, Any]) -> str:
        """
        Format evidence data as JSON string.
        
        Args:
            evidence_data: Evidence dictionary from collect_request_response
        
        Returns:
            JSON formatted evidence string
        """
        try:
            # Create a serializable copy (handle bytes, etc.)
            serializable_evidence = {}
            
            for key, value in evidence_data.items():
                if isinstance(value, dict):
                    serializable_evidence[key] = {}
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, bytes):
                            serializable_evidence[key][sub_key] = sub_value.decode('utf-8', errors='ignore')
                        else:
                            serializable_evidence[key][sub_key] = sub_value
                else:
                    serializable_evidence[key] = value
            
            return json.dumps(serializable_evidence, indent=2, ensure_ascii=False)
        except Exception:
            # Fallback to simple string representation
            return str(evidence_data)
    
    @staticmethod
    def extract_relevant_headers(response: requests.Response, include_all: bool = False) -> Dict[str, str]:
        """
        Extract relevant security headers from response.
        
        Args:
            response: The response object
            include_all: If True, include all headers; otherwise only security-related
        
        Returns:
            Dictionary of headers
        """
        if include_all:
            return dict(response.headers)
        
        security_headers = [
            'Content-Type',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection',
            'Server',
            'X-Powered-By',
            'Set-Cookie',
            'Location',
            'WWW-Authenticate',
        ]
        
        relevant = {}
        for header in security_headers:
            if header in response.headers:
                relevant[header] = response.headers[header]
        
        return relevant
