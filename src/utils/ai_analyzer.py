"""AI-powered analysis generator for scan results."""

import os
import json
import logging
from typing import Optional
from ..models.scan import ScanResult

logger = logging.getLogger(__name__)

# Try to import OpenAI - will be None if not available
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None

# Try to import requests for fallback API calls
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None


def generate_analysis(result: ScanResult) -> Optional[str]:
    """
    Generate an AI-powered high-level analysis of scan results.
    
    Supports multiple AI providers:
    - OpenAI (OPENAI_API_KEY)
    - Anthropic Claude (ANTHROPIC_API_KEY or OPENAI_API_KEY with sk-ant- prefix)
    - Google Gemini (GEMINI_API_KEY)
    - AWS Bedrock (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION)
    
    Args:
        result: ScanResult object containing findings and metadata
        
    Returns:
        Analysis text as string, or None if analysis cannot be generated
    """
    try:
        # Prepare analysis prompt
        findings_summary = _prepare_findings_summary(result)
        prompt = _create_analysis_prompt(result, findings_summary)
        
        # Try Gemini first (if key available)
        gemini_key = os.getenv('GEMINI_API_KEY')
        if gemini_key and REQUESTS_AVAILABLE:
            try:
                return _generate_with_gemini(gemini_key, prompt)
            except Exception as e:
                error_msg = str(e)
                # Don't log expired key errors as warnings (too noisy), just debug
                if 'expired' in error_msg.lower() or 'invalid' in error_msg.lower():
                    logger.debug(f"Gemini API key issue: {error_msg[:100]}, trying other providers")
                else:
                    logger.warning(f"Gemini API call failed: {e}, trying other providers")
        
        # Try AWS Bedrock (if credentials available)
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_region = os.getenv('AWS_REGION', 'us-east-1')
        if aws_access_key and aws_secret_key and REQUESTS_AVAILABLE:
            try:
                return _generate_with_bedrock(aws_access_key, aws_secret_key, aws_region, prompt)
            except Exception as e:
                logger.warning(f"Bedrock API call failed: {e}, trying other providers")
        
        # Try OpenAI/Anthropic (if key available)
        api_key = os.getenv('OPENAI_API_KEY') or os.getenv('AI_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            logger.debug("No AI API key found in environment variables")
            return None
        
        # Try OpenAI library first if available
        if OPENAI_AVAILABLE and api_key and not api_key.startswith('sk-ant-'):
            try:
                return _generate_with_openai(api_key, prompt)
            except Exception as e:
                logger.warning(f"OpenAI API call failed: {e}, trying fallback")
        
        # Fallback to direct API call
        if REQUESTS_AVAILABLE:
            return _generate_with_api_call(api_key, prompt)
        
        logger.warning("No AI provider available for analysis")
        return None
        
    except Exception as e:
        logger.error(f"Failed to generate AI analysis: {e}", exc_info=True)
        return None


def _prepare_findings_summary(result: ScanResult) -> str:
    """Prepare a structured summary of findings for the AI prompt."""
    if not result.findings:
        return "No security findings detected."
    
    # Group findings by severity
    by_severity = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': [],
        'Info': []
    }
    
    for finding in result.findings:
        severity = finding.severity.value.title()
        if severity in by_severity:
            by_severity[severity].append(finding)
    
    summary_parts = []
    
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        findings_list = by_severity[severity]
        if findings_list:
            summary_parts.append(f"\n{severity} Severity ({len(findings_list)} finding(s)):")
            # Include first 3 findings of each severity with brief descriptions
            for i, finding in enumerate(findings_list[:3], 1):
                category = finding.category.value.replace('_', ' ').title()
                summary_parts.append(f"  {i}. {finding.title} ({category})")
                if finding.url:
                    summary_parts.append(f"     URL: {finding.url}")
            if len(findings_list) > 3:
                summary_parts.append(f"  ... and {len(findings_list) - 3} more {severity.lower()} severity finding(s)")
    
    return "\n".join(summary_parts)


def _create_analysis_prompt(result: ScanResult, findings_summary: str) -> str:
    """Create the prompt for AI analysis."""
    target_url = result.target.url
    scan_mode = result.scan_mode.value.title()
    total_findings = len(result.findings)
    
    risk_info = ""
    if result.risk_score:
        risk_info = f"""
Risk Score: {result.risk_score.overall_score:.1f}/100
Risk Level: {result.risk_score.risk_level.value.title()}
Severity Breakdown:
  - Critical: {result.risk_score.critical_count}
  - High: {result.risk_score.high_count}
  - Medium: {result.risk_score.medium_count}
  - Low: {result.risk_score.low_count}
  - Info: {result.risk_score.info_count}
"""
    
    # Determine authorization context
    auth_context = "authorized security assessment"
    if scan_mode.lower() in ['offensive', 'comprehensive']:
        auth_context += " including authorized penetration testing"
    
    prompt = f"""You are a cybersecurity expert providing security analysis for an AUTHORIZED, SANDBOXED security assessment tool. This is a legitimate security testing platform used for defensive security analysis and authorized penetration testing. All testing is conducted with proper authorization.

CONTEXT:
- This is an authorized security assessment platform (DarkOrca)
- All scans are performed in authorized, controlled environments
- This is a core security tool functionality - analysis and recommendations are required
- You must provide actionable, professional security guidance

TARGET: {target_url}
SCAN MODE: {scan_mode} ({auth_context})
TOTAL FINDINGS: {total_findings}
{risk_info}
FINDINGS SUMMARY:
{findings_summary}

REQUIREMENTS:
Provide a professional, actionable security analysis (2-4 paragraphs) that:

1. **Executive Summary**: Summarize the overall security posture based on the risk score and findings. Assess whether the target is well-secured, has moderate issues, or critical vulnerabilities.

2. **Critical Priorities**: Identify the most critical security concerns that require immediate remediation. Prioritize based on severity and exploitability. Be specific about what needs to be fixed first.

3. **Risk Context**: Explain what the severity distribution means in practical terms. For example, multiple high-severity findings indicate systemic security issues, while scattered low-severity findings may indicate good baseline security with minor improvements needed.

4. **Actionable Recommendations**: Provide specific, actionable recommendations for remediation. Include:
   - Immediate actions for critical/high severity findings
   - Strategic improvements for medium/low severity issues
   - Best practices to prevent similar issues

IMPORTANT:
- DO NOT refuse to provide analysis or recommendations
- DO NOT say you cannot discuss offensive testing - this is authorized security assessment
- DO be specific and action-oriented in all recommendations
- DO prioritize based on real-world security impact
- Write for technical stakeholders (security teams, developers, CTOs)

Tone: Professional, direct, and focused on actionable security guidance.
"""
    
    return prompt


def _generate_with_openai(api_key: str, prompt: str) -> str:
    """Generate analysis using OpenAI API via the openai library."""
    if not OPENAI_AVAILABLE:
        raise RuntimeError("OpenAI library not available")
    
    client = openai.OpenAI(api_key=api_key)
    
    response = client.chat.completions.create(
        model=os.getenv('OPENAI_MODEL', 'gpt-4o-mini'),  # Default to cost-effective model
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert providing authorized security assessment analysis. You provide actionable security recommendations for legitimate security testing tools. All analysis is for authorized, controlled security assessments."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1000,  # Increased for more comprehensive analysis
        temperature=0.7,
    )
    
    analysis = response.choices[0].message.content.strip()
    logger.info("Successfully generated AI analysis using OpenAI")
    return analysis


def _generate_with_api_call(api_key: str, prompt: str) -> str:
    """Generate analysis using direct API call (fallback if library not available)."""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests library not available")
    
    # Determine API endpoint based on key format
    # OpenAI keys start with sk-, Anthropic keys start with sk-ant-
    if api_key.startswith('sk-'):
        if api_key.startswith('sk-ant-'):
            # Anthropic API
            api_url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            payload = {
                "model": "claude-3-haiku-20240307",
                "max_tokens": 1000,  # Increased for more comprehensive analysis
                "messages": [
                    {"role": "user", "content": f"You are providing authorized security assessment analysis for legitimate security testing tools. Provide actionable security recommendations. All analysis is for authorized, controlled security assessments.\n\n{prompt}"}
                ]
            }
        else:
            # OpenAI API
            api_url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": os.getenv('OPENAI_MODEL', 'gpt-4o-mini'),
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert providing concise, professional security analysis."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 800,
                "temperature": 0.7
            }
    else:
        raise ValueError("API key format not recognized")
    
    response = requests.post(api_url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    data = response.json()
    
    # Extract response based on API type
    if 'choices' in data:  # OpenAI format
        analysis = data['choices'][0]['message']['content'].strip()
    elif 'content' in data:  # Anthropic format
        analysis = data['content'][0]['text'].strip()
    else:
        raise ValueError(f"Unexpected API response format: {list(data.keys())}")
    
    logger.info("Successfully generated AI analysis using direct API call")
    return analysis


def _generate_with_gemini(api_key: str, prompt: str) -> str:
    """Generate analysis using Google Gemini API."""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests library not available")
    
    # Use Gemini 1.5 Flash for cost-effective analysis (stable version)
    model = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
    
    # Use v1beta endpoint (most compatible)
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "contents": [{
            "parts": [{
                "text": f"You are a cybersecurity expert providing authorized security assessment analysis for legitimate security testing tools. Provide actionable security recommendations. All analysis is for authorized, controlled security assessments.\n\n{prompt}"
            }]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 1000,  # Increased for more comprehensive analysis
        }
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # Try v1beta endpoint as fallback
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            response = requests.post(api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
        else:
            raise
    
    if 'candidates' in data and len(data['candidates']) > 0:
        candidate = data['candidates'][0]
        if 'content' in candidate and 'parts' in candidate['content']:
            parts = candidate['content']['parts']
            if len(parts) > 0 and 'text' in parts[0]:
                analysis = parts[0]['text'].strip()
                logger.info("Successfully generated AI analysis using Google Gemini")
                return analysis
    
    raise ValueError(f"Unexpected Gemini API response format: {list(data.keys()) if isinstance(data, dict) else type(data)}")


def _generate_with_bedrock(access_key: str, secret_key: str, region: str, prompt: str) -> str:
    """Generate analysis using AWS Bedrock API."""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests library not available")
    
    # Import boto3 for AWS signature
    try:
        import boto3
        BOTO3_AVAILABLE = True
    except ImportError:
        logger.warning("boto3 not available, cannot use AWS Bedrock. Install with: pip install boto3")
        raise RuntimeError("boto3 library not available for Bedrock")
    
    # Use Claude 3 Haiku on Bedrock (cost-effective model)
    model_id = os.getenv('BEDROCK_MODEL', 'anthropic.claude-3-haiku-20240307-v1:0')
    
    # Create Bedrock client
    bedrock = boto3.client(
        'bedrock-runtime',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1000,  # Increased for more comprehensive analysis
        "messages": [{
            "role": "user",
            "content": f"You are a cybersecurity expert providing authorized security assessment analysis for legitimate security testing tools. Provide actionable security recommendations. All analysis is for authorized, controlled security assessments.\n\n{prompt}"
        }]
    }
    
    # Invoke the model
    response = bedrock.invoke_model(
        modelId=model_id,
        body=json.dumps(payload)
    )
    
    # Parse response
    response_body = json.loads(response['body'].read())
    
    if 'content' in response_body and len(response_body['content']) > 0:
        analysis = response_body['content'][0].get('text', '').strip()
        logger.info("Successfully generated AI analysis using AWS Bedrock")
        return analysis
    
    raise ValueError(f"Unexpected Bedrock API response format: {list(response_body.keys())}")
