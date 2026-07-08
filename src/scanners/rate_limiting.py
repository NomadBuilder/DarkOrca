"""Rate limiting detection and analysis."""

import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from collections import defaultdict

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class RateLimitingAnalyzer(BaseScanner):
    """Analyze rate limiting configuration."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize rate limiting analyzer."""
        super().__init__(
            name="rate_limiting",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze rate limiting."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            # Always check headers first (non-intrusive)
            findings.extend(self._check_rate_limit_headers(target.url))
            
            # Rate limiting testing - more aggressive in offensive mode
            if self.scan_mode == ScanMode.OFFENSIVE:
                # Simulate DDoS-like burst in offensive mode
                findings.extend(self._test_rate_limiting_burst(target.url))
            else:
                # Conservative test in defensive mode
                findings.extend(self._test_rate_limiting_conservative(target.url))
            
        except Exception as e:
            logger.error(f"Rate limiting analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _make_request(self, url: str, request_id: int) -> Dict[str, Any]:
        """Make a single request and return response data."""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=10, allow_redirects=False)
            elapsed = time.time() - start_time
            
            return {
                'request_id': request_id,
                'status': response.status_code,
                'headers': dict(response.headers),
                'elapsed': elapsed,
                'success': True,
                'timestamp': start_time
            }
        except Exception as e:
            return {
                'request_id': request_id,
                'status': None,
                'headers': {},
                'elapsed': None,
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _test_rate_limiting_burst(self, url: str) -> List[Finding]:
        """Test rate limiting with a DDoS-like burst of concurrent requests (offensive mode only)."""
        findings = []
        
        try:
            logger.info(f"Testing rate limiting with burst attack simulation on {url}")
            
            # Phase 1: Baseline - establish normal response characteristics
            # Make multiple requests to get a reliable baseline (median, not just average)
            baseline_responses = []
            baseline_count = 5  # More samples for better baseline
            for i in range(baseline_count):
                result = self._make_request(url, i)
                baseline_responses.append(result)
                time.sleep(0.3)  # Normal spacing between baseline requests
            
            # Calculate baseline metrics
            baseline_times = [r['elapsed'] for r in baseline_responses if r['elapsed'] is not None]
            baseline_status_codes = [r['status'] for r in baseline_responses if r['success'] and r['status']]
            
            if not baseline_times or not baseline_status_codes:
                # Can't establish baseline - endpoint might be down or unreachable
                logger.warning(f"Could not establish baseline for {url} - endpoint may be unreachable")
                return findings
            
            baseline_times_sorted = sorted(baseline_times)
            baseline_median_time = baseline_times_sorted[len(baseline_times_sorted) // 2]  # Median is more robust than mean
            baseline_p95_time = baseline_times_sorted[int(len(baseline_times_sorted) * 0.95)] if len(baseline_times_sorted) > 4 else baseline_times_sorted[-1]
            baseline_success_rate = len(baseline_status_codes) / baseline_count
            
            # Verify baseline is healthy
            if baseline_success_rate < 0.8:  # Less than 80% success in baseline
                logger.warning(f"Baseline success rate too low ({baseline_success_rate:.1%}) - endpoint may be unreliable")
                return findings
            
            # Phase 2: Burst attack simulation - send many concurrent requests
            # Simulate a realistic DDoS-like attack: 1000 requests over 10 seconds (~100 req/sec)
            # This provides a significant load to properly test rate limiting
            burst_size = 200000
            burst_duration = 30.0  # seconds
            requests_per_second = burst_size / burst_duration
            
            logger.info(f"Sending {burst_size} concurrent requests over {burst_duration}s (simulating ~{requests_per_second:.1f} req/s) - DDoS simulation")
            
            burst_responses = []
            start_time = time.time()
            
            # Use ThreadPoolExecutor for concurrent requests (scale workers with request volume)
            # With 2000 requests, we need higher concurrency to generate realistic load
            with ThreadPoolExecutor(max_workers=200) as executor:
                futures = [executor.submit(self._make_request, url, i) for i in range(burst_size)]
                completed = 0
                for future in as_completed(futures):
                    elapsed = time.time() - start_time
                    if elapsed > burst_duration + 90:  # Extended safety timeout for 2000 requests
                        logger.warning(f"Burst test timeout after {elapsed:.1f}s - collected {completed}/{burst_size} responses")
                        break
                    try:
                        result = future.result(timeout=30)  # Higher timeout per request (handles rate limiting delays)
                        burst_responses.append(result)
                        completed += 1
                    except Exception as e:
                        error_msg = str(e)
                        error_type = type(e).__name__
                        logger.debug(f"Request {completed} failed in burst test: {error_msg}")
                        burst_responses.append({
                            'request_id': completed,
                            'status': None,
                            'success': False,
                            'error': error_msg,
                            'error_type': error_type,
                            'timestamp': time.time()
                        })
                        completed += 1
                
                logger.info(f"Burst test completed: {completed}/{burst_size} requests finished in {time.time() - start_time:.1f}s")
            
            # Phase 3: Wait longer and check if service recovers (rate limits often have 15-60s windows)
            # With a 30s burst, we should wait longer to see recovery
            logger.info("Waiting 20 seconds to check if service recovers after rate limit window...")
            time.sleep(20)
            
            recovery_responses = []
            for i in range(3):
                result = self._make_request(url, i + burst_size)
                recovery_responses.append(result)
                time.sleep(0.5)
            
            # Analyze results with robust metrics
            # Filter out failed requests (timeouts, connection errors) from analysis
            successful_burst_responses = [r for r in burst_responses if r.get('success') and r.get('status')]
            failed_burst_responses = [r for r in burst_responses if not r.get('success')]
            
            burst_status_codes = [r['status'] for r in successful_burst_responses]
            recovery_status_codes = [r['status'] for r in recovery_responses if r.get('success') and r.get('status')]
            
            # Calculate failure rate (network errors, timeouts, etc.)
            failure_rate = (len(failed_burst_responses) / len(burst_responses) * 100) if burst_responses else 0
            failure_types = defaultdict(int)
            for r in failed_burst_responses:
                error_type = r.get('error_type', 'Unknown')
                failure_types[error_type] += 1
            
            # Count status codes (only from successful requests)
            status_counts = defaultdict(int)
            for r in successful_burst_responses:
                status_counts[r['status']] += 1
            
            # Calculate response time metrics (more robust analysis)
            # Only use successful requests for timing analysis
            burst_times = [r['elapsed'] for r in successful_burst_responses if r.get('elapsed') is not None]
            
            if not burst_times:
                logger.warning(f"No valid response times collected during burst test for {url} - all requests may have failed")
                # Still report if we have status codes
                if burst_status_codes:
                    # Report as finding but note the issue
                    findings.append(Finding(
                        title="Rate Limiting Test - Data Collection Issue",
                        description=f"Burst test completed but response time data unavailable. {len(burst_responses)} requests sent, {len(successful_burst_responses)} successful responses. Status codes: {dict(status_counts)}. Failure rate: {failure_rate:.1f}%.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=url,
                        evidence=f"Burst test: {burst_size} requests. Successful: {len(successful_burst_responses)}, Failed: {len(failed_burst_responses)}. Failure types: {dict(failure_types)}.",
                    ))
                return findings
            
            burst_times_sorted = sorted(burst_times)
            median_burst_time = burst_times_sorted[len(burst_times_sorted) // 2]
            p95_burst_time = burst_times_sorted[int(len(burst_times_sorted) * 0.95)]
            p99_burst_time = burst_times_sorted[int(len(burst_times_sorted) * 0.99)] if len(burst_times_sorted) > 100 else burst_times_sorted[-1]
            
            # Calculate degradation metrics
            time_degradation_ratio = median_burst_time / baseline_median_time if baseline_median_time > 0 else 1.0
            p95_degradation_ratio = p95_burst_time / baseline_p95_time if baseline_p95_time > 0 else 1.0
            
            # Calculate success/failure rates (only count HTTP responses, not network failures)
            total_http_responses = len(successful_burst_responses)  # Only successful HTTP requests
            total_all_requests = len(burst_responses)  # All attempts including failures
            
            successful_requests = status_counts.get(200, 0)
            client_errors = sum(count for code, count in status_counts.items() if 400 <= code < 500)
            server_errors = sum(count for code, count in status_counts.items() if code >= 500)
            
            # Success rate based on HTTP responses only (more meaningful)
            success_rate = (successful_requests / total_http_responses * 100) if total_http_responses > 0 else 0
            # Error rate includes both HTTP errors and network failures
            http_error_rate = ((client_errors + server_errors) / total_http_responses * 100) if total_http_responses > 0 else 0
            total_error_rate = (((client_errors + server_errors + len(failed_burst_responses)) / total_all_requests) * 100) if total_all_requests > 0 else 0
            
            # Check for rate limiting indicators
            rate_limited_during_burst = False
            rate_limit_evidence = []
            
            # Check for 429 status codes (explicit rate limiting)
            if 429 in status_counts:
                rate_limited_during_burst = True
                rate_limit_evidence.append(f"Received {status_counts[429]} '429 Too Many Requests' responses ({status_counts[429]/total_http_responses*100:.1f}% of HTTP responses)")
            
            # Check for Retry-After headers
            retry_after_found = False
            retry_after_values = []
            for r in burst_responses:
                headers = r.get('headers', {})
                if 'Retry-After' in headers:
                    retry_after_found = True
                    retry_after_values.append(headers['Retry-After'])
            
            if retry_after_values:
                unique_retry_after = list(set(retry_after_values))
                rate_limit_evidence.append(f"Retry-After header detected: {', '.join(unique_retry_after[:3])}")
            
            # Check for rate limit headers
            rate_limit_headers_found = []
            for r in burst_responses:
                headers = r.get('headers', {})
                if 'X-RateLimit-Limit' in headers or 'RateLimit-Limit' in headers:
                    limit = headers.get('X-RateLimit-Limit') or headers.get('RateLimit-Limit')
                    remaining = headers.get('X-RateLimit-Remaining') or headers.get('RateLimit-Remaining')
                    reset = headers.get('X-RateLimit-Reset') or headers.get('RateLimit-Reset')
                    rate_limit_headers_found.append({
                        'limit': limit, 
                        'remaining': remaining,
                        'reset': reset
                    })
                    break  # Only need one sample
            
            # Detect throttling through response time degradation
            significant_throttling = False
            if time_degradation_ratio > 3.0:  # Response times >3x slower suggests throttling/degradation
                significant_throttling = True
                rate_limit_evidence.append(f"Severe response time degradation: median {baseline_median_time:.2f}s → {median_burst_time:.2f}s ({time_degradation_ratio:.1f}x slower)")
            elif time_degradation_ratio > 2.0:
                rate_limit_evidence.append(f"Moderate response time increase: median {baseline_median_time:.2f}s → {median_burst_time:.2f}s ({time_degradation_ratio:.1f}x slower, possible throttling)")
            
            # Detect DoS symptoms (high error rates)
            # Consider both HTTP errors and network failures (timeouts, connection errors)
            dos_symptoms_http = http_error_rate > 5.0  # More than 5% HTTP errors suggests overload
            dos_symptoms_total = total_error_rate > 10.0  # High total failure rate (network + HTTP)
            
            if dos_symptoms_http:
                rate_limit_evidence.append(f"High HTTP error rate during load: {http_error_rate:.1f}% ({server_errors} server errors, {client_errors} client errors)")
            if dos_symptoms_total and failure_rate > 5.0:
                rate_limit_evidence.append(f"High failure rate during load: {total_error_rate:.1f}% (including {failure_rate:.1f}% network failures: {dict(failure_types)})")
            
            # Check if service recovered (compare recovery to baseline)
            recovery_times = [r['elapsed'] for r in recovery_responses if r['elapsed'] is not None]
            service_recovered = False
            recovery_metrics = {}
            
            if recovery_status_codes:
                recovery_success_rate = sum(1 for s in recovery_status_codes if s == 200) / len(recovery_status_codes)
                service_recovered = recovery_success_rate >= 0.8  # 80%+ success indicates recovery
                
                if recovery_times:
                    median_recovery_time = sorted(recovery_times)[len(recovery_times) // 2]
                    recovery_metrics = {
                        'success_rate': recovery_success_rate,
                        'median_time': median_recovery_time,
                        'baseline_comparison': 'similar' if abs(median_recovery_time - baseline_median_time) < baseline_median_time * 0.5 else 'degraded'
                    }
            
            # Generate findings
            if rate_limited_during_burst or retry_after_found:
                evidence_summary = "; ".join(rate_limit_evidence) if rate_limit_evidence else "Rate limiting indicators detected"
                
                findings.append(Finding(
                    title="Rate Limiting Detected and Active",
                    description=f"Rate limiting is implemented and enforced. During burst test ({burst_size} requests over {burst_duration}s, ~{requests_per_second:.1f} req/s): {evidence_summary}. Service {'recovered to baseline performance' if service_recovered and recovery_metrics.get('baseline_comparison') == 'similar' else ('recovered but performance degraded' if service_recovered else 'may still be affected by')} rate limiting window.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                    evidence=f"Burst test: {burst_size} requests, {len(burst_responses)} responses ({len(successful_burst_responses)} HTTP, {len(failed_burst_responses)} failures). Status codes: {dict(status_counts)}. Baseline median: {baseline_median_time:.2f}s, Burst median: {median_burst_time:.2f}s ({time_degradation_ratio:.1f}x). Success rate: {success_rate:.1f}%. Recovery: {recovery_metrics}",
                    metadata={
                        'burst_size': burst_size,
                        'burst_duration': burst_duration,
                        'requests_per_second': requests_per_second,
                        'status_counts': dict(status_counts),
                        'baseline_median_time': baseline_median_time,
                        'burst_median_time': median_burst_time,
                        'time_degradation_ratio': time_degradation_ratio,
                        'success_rate': success_rate,
                        'http_error_rate': http_error_rate,
                        'total_error_rate': total_error_rate,
                        'failure_rate': failure_rate,
                        'rate_limited': True,
                        'service_recovered': service_recovered,
                        'recovery_metrics': recovery_metrics
                    }
                ))
            elif rate_limit_headers_found:
                findings.append(Finding(
                    title="Rate Limit Headers Present",
                    description=f"Server provides rate limit information in headers: {rate_limit_headers_found[0]}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                    metadata={'rate_limit_info': rate_limit_headers_found[0]}
                ))
            else:
                # No rate limiting detected - this is a DoS risk
                # Availability is a security property - lack of rate limiting enables DoS attacks
                # With expensive request processing (XML parsing, file uploads, etc.), this becomes critical
                # Note: success_rate, error rates, and degradation metrics already calculated above
                
                # Determine severity based on actual impact observed
                # Consider multiple factors: error rate, response time degradation, service recovery
                severity_factors = []
                
                # Factor 1: Error rate (consider both HTTP errors and network failures)
                if total_error_rate > 15 or http_error_rate > 10:
                    severity_factors.append('high_error_rate')
                elif total_error_rate > 10 or http_error_rate > 5:
                    severity_factors.append('moderate_error_rate')
                
                # Factor 1b: Network failure rate (indicates site may be overwhelmed)
                if failure_rate > 10:
                    severity_factors.append('high_network_failure_rate')
                elif failure_rate > 5:
                    severity_factors.append('moderate_network_failure_rate')
                
                # Factor 2: Response time degradation
                if time_degradation_ratio > 5.0:
                    severity_factors.append('severe_degradation')
                elif time_degradation_ratio > 3.0:
                    severity_factors.append('significant_degradation')
                elif time_degradation_ratio > 2.0:
                    severity_factors.append('moderate_degradation')
                
                # Factor 3: Recovery status
                if not service_recovered:
                    severity_factors.append('no_recovery')
                elif recovery_metrics.get('baseline_comparison') == 'degraded':
                    severity_factors.append('degraded_recovery')
                
                # Determine severity based on factors
                if 'high_error_rate' in severity_factors or 'severe_degradation' in severity_factors or 'no_recovery' in severity_factors:
                    severity = FindingSeverity.MEDIUM  # Site showed clear signs of DoS impact
                    risk_description = f"Site showed clear signs of instability during load test: {success_rate:.1f}% success rate, {total_error_rate:.1f}% total errors ({http_error_rate:.1f}% HTTP, {failure_rate:.1f}% network failures), response times {time_degradation_ratio:.1f}x slower than baseline."
                elif 'moderate_error_rate' in severity_factors or 'significant_degradation' in severity_factors or 'degraded_recovery' in severity_factors:
                    severity = FindingSeverity.LOW  # Site showed moderate impact
                    risk_description = f"Site showed signs of stress during load test: {success_rate:.1f}% success rate, response times {time_degradation_ratio:.1f}x slower."
                else:
                    severity = FindingSeverity.LOW  # Site handled load but lacks protection
                    risk_description = f"Site processed requests ({success_rate:.1f}% success) but lacks rate limiting protection, making it vulnerable to DoS attacks."
                
                findings.append(Finding(
                    title="Rate Limiting Not Detected - DoS Risk",
                    description=f"No rate limiting detected during burst test ({burst_size} requests over {burst_duration}s, ~{requests_per_second:.1f} req/s). {risk_description} This indicates susceptibility to denial-of-service attacks, especially when combined with expensive request processing (XML parsing, file uploads, complex queries). Availability is a security property, and lack of rate limiting enables application-layer DoS attacks.",
                    severity=severity,
                    category=FindingCategory.WEAK_SECURITY,  # Changed from FINGERPRINTING - this is a security weakness
                    source_scanner=self.name,
                    url=url,
                    evidence=f"Burst test: {burst_size} requests over {burst_duration}s (~{requests_per_second:.1f} req/s). Collected: {len(successful_burst_responses)} HTTP responses, {len(failed_burst_responses)} failures ({failure_rate:.1f}%). Status codes: {dict(status_counts)}. Success rate: {success_rate:.1f}%, HTTP error rate: {http_error_rate:.1f}%, Total error rate: {total_error_rate:.1f}%. Baseline median: {baseline_median_time:.2f}s, Burst median: {median_burst_time:.2f}s (degradation: {time_degradation_ratio:.1f}x). P95 times: baseline {baseline_p95_time:.2f}s → burst {p95_burst_time:.2f}s. Recovery: {service_recovered}, {recovery_metrics.get('baseline_comparison', 'unknown')}. Failure types: {dict(failure_types)}. No rate limiting indicators (429, Retry-After) detected.",
                    remediation=f"Implement rate limiting to protect against DoS attacks. Set reasonable limits (e.g., {int(requests_per_second * 0.1):.0f}-{int(requests_per_second * 0.5):.0f} req/s per IP) and enforce request throttling. Consider per-endpoint limits for expensive operations (XML processing, file uploads). Rate limiting is critical for availability and prevents application-layer DoS attacks.",
                    references=[
                        "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                        "https://owasp.org/www-project-top-ten/OWASP_Top_Ten_Cheat_Sheet/"
                    ],
                    metadata={
                        'burst_size': burst_size,
                        'burst_duration': burst_duration,
                        'requests_per_second': requests_per_second,
                        'status_counts': dict(status_counts),
                        'baseline_metrics': {
                            'median_time': baseline_median_time,
                            'p95_time': baseline_p95_time,
                            'success_rate': baseline_success_rate
                        },
                        'burst_metrics': {
                            'median_time': median_burst_time,
                            'p95_time': p95_burst_time,
                            'p99_time': p99_burst_time,
                            'success_rate': success_rate,
                            'http_error_rate': http_error_rate,
                            'total_error_rate': total_error_rate,
                            'failure_rate': failure_rate,
                            'server_errors': server_errors,
                            'client_errors': client_errors,
                            'network_failures': len(failed_burst_responses),
                            'failure_types': dict(failure_types)
                        },
                        'degradation': {
                            'time_ratio': time_degradation_ratio,
                            'p95_ratio': p95_degradation_ratio,
                            'significant_throttling': significant_throttling,
                            'dos_symptoms_http': dos_symptoms_http,
                            'dos_symptoms_total': dos_symptoms_total
                        },
                        'recovery': {
                            'recovered': service_recovered,
                            'metrics': recovery_metrics
                        },
                        'rate_limited': False,
                        'dos_risk': True,
                        'severity_factors': severity_factors
                    }
                ))
        
        except Exception as e:
            logger.debug(f"Rate limiting burst test error: {e}")
        
        return findings
    
    def _test_rate_limiting_conservative(self, url: str) -> List[Finding]:
        """Conservative rate limiting test (defensive mode) - makes slow, respectful requests."""
        findings = []
        
        try:
            # Make 10 requests with delays (respectful)
            responses = []
            for i in range(10):
                result = self._make_request(url, i)
                responses.append(result)
                time.sleep(0.2)  # Respectful delay
            
            status_codes = [r['status'] for r in responses if r['success'] and r['status']]
            status_counts = defaultdict(int)
            for code in status_codes:
                status_counts[code] += 1
            
            rate_limited = False
            rate_limit_headers = []
            
            for response in responses:
                headers = response.get('headers', {})
                
                if 'X-RateLimit-Limit' in headers or 'X-RateLimit-Remaining' in headers:
                    rate_limit_headers.append({
                        'limit': headers.get('X-RateLimit-Limit'),
                        'remaining': headers.get('X-RateLimit-Remaining'),
                        'reset': headers.get('X-RateLimit-Reset'),
                    })
                
                if 'Retry-After' in headers:
                    rate_limited = True
                
                if response.get('status') == 429:
                    rate_limited = True
            
            if rate_limited:
                findings.append(Finding(
                    title="Rate Limiting Detected",
                    description="Rate limiting appears to be implemented. Use offensive mode for detailed burst testing.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                ))
            elif rate_limit_headers:
                findings.append(Finding(
                    title="Rate Limit Headers Present",
                    description=f"Server provides rate limit information in headers: {rate_limit_headers[0]}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                    metadata={'rate_limit_info': rate_limit_headers[0]}
                ))
        
        except Exception as e:
            logger.debug(f"Rate limiting conservative test error: {e}")
        
        return findings
    
    def _check_rate_limit_headers(self, url: str) -> List[Finding]:
        """Check for rate limit headers in response."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            rate_limit_indicators = [
                'X-RateLimit-Limit',
                'X-RateLimit-Remaining',
                'X-RateLimit-Reset',
                'RateLimit-Limit',
                'RateLimit-Remaining',
                'RateLimit-Reset',
            ]
            
            found_headers = {k: headers.get(k) for k in rate_limit_indicators if headers.get(k)}
            
            if found_headers:
                findings.append(Finding(
                    title="Rate Limit Headers Configured",
                    description=f"Server provides rate limit information: {found_headers}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                    metadata=found_headers
                ))
        
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"Rate limit headers check error: {e}")
        
        return findings
    
    def is_available(self) -> bool:
        """Rate limiting analyzer is always available."""
        return True

