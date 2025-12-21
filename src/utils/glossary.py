"""Glossary data for security terms and concepts."""

from typing import Dict, List, Any


class Glossary:
    """Comprehensive glossary of security terms and concepts used in DarkOrca."""
    
    @staticmethod
    def get_all_terms() -> List[Dict[str, Any]]:
        """Get all glossary terms organized by category."""
        return [
            # Scan Modes
            {
                "term": "Defensive Mode",
                "category": "Scan Modes",
                "definition": "A passive, read-only scanning mode that performs reconnaissance and discovery without attempting exploitation. Safe for use on production systems as it doesn't attempt to exploit vulnerabilities.",
                "example": "Checking for exposed endpoints, security headers, SSL configuration, and information disclosure."
            },
            {
                "term": "Offensive Mode",
                "category": "Scan Modes",
                "definition": "An active scanning mode that attempts to exploit identified vulnerabilities to confirm their existence. Should only be used with explicit authorization as it may impact system stability or trigger security alerts.",
                "example": "Attempting SQL injection payloads, XSS exploits, and command injection attacks to verify vulnerabilities."
            },
            {
                "term": "Comprehensive Mode",
                "category": "Scan Modes",
                "definition": "A combined scanning mode that performs both defensive reconnaissance and offensive exploitation testing. Provides the most thorough security assessment.",
                "example": "First performs passive discovery, then attempts exploitation of identified vulnerabilities."
            },
            
            # Risk Levels
            {
                "term": "Critical Risk",
                "category": "Risk Levels",
                "definition": "The highest risk level, indicating severe security issues that require immediate attention. Typically includes vulnerabilities that could lead to system compromise, data breach, or complete loss of confidentiality/integrity.",
                "example": "Remote code execution, SQL injection allowing data extraction, or authentication bypass vulnerabilities."
            },
            {
                "term": "High Risk",
                "category": "Risk Levels",
                "definition": "Serious security issues that should be prioritized for remediation. These vulnerabilities could be exploited to gain unauthorized access or cause significant damage.",
                "example": "Privilege escalation vulnerabilities, sensitive data exposure, or insecure authentication mechanisms."
            },
            {
                "term": "Medium Risk",
                "category": "Risk Levels",
                "definition": "Moderate security issues that should be addressed but may require specific conditions or additional steps to exploit. These pose a meaningful but not immediate threat.",
                "example": "Missing security headers, weak encryption, or information disclosure that could aid attackers."
            },
            {
                "term": "Low Risk",
                "category": "Risk Levels",
                "definition": "Minor security issues or best practice violations that have limited impact. These may become more serious when combined with other vulnerabilities.",
                "example": "Outdated software versions without known exploits, verbose error messages, or minor configuration issues."
            },
            {
                "term": "Minimal Risk",
                "category": "Risk Levels",
                "definition": "The lowest risk level, indicating informational findings or very minor issues that have negligible security impact.",
                "example": "Informational banners, technology stack identification, or minor best practice suggestions."
            },
            
            # Finding Categories
            {
                "term": "Vulnerability",
                "category": "Finding Categories",
                "definition": "A security weakness or flaw in software, hardware, or configuration that can be exploited to compromise the system. Vulnerabilities are specific issues that can lead to security breaches.",
                "example": "SQL injection, XSS, command injection, or buffer overflow vulnerabilities."
            },
            {
                "term": "Misconfiguration",
                "category": "Finding Categories",
                "definition": "Security issues resulting from incorrect or insecure configuration of systems, applications, or services. Often easier to fix than vulnerabilities as they don't require code changes.",
                "example": "Default passwords, exposed admin panels, overly permissive file permissions, or missing security headers."
            },
            {
                "term": "Information Disclosure",
                "category": "Finding Categories",
                "definition": "Issues that reveal sensitive information that could aid attackers in reconnaissance or exploitation. This includes exposed files, error messages, or leaked credentials.",
                "example": "Backup files accessible via web, error messages revealing stack traces, or exposed API keys in source code."
            },
            {
                "term": "Exposed Endpoint",
                "category": "Finding Categories",
                "definition": "Endpoints, files, or services that are publicly accessible but should not be. These can provide attack surfaces or reveal sensitive information.",
                "example": "Admin panels, API endpoints, debug interfaces, or internal services exposed to the internet."
            },
            {
                "term": "Weak Security",
                "category": "Finding Categories",
                "definition": "Security controls or mechanisms that are present but implemented poorly or with insufficient strength. These reduce the effectiveness of security measures.",
                "example": "Weak encryption algorithms, insufficient password policies, or rate limiting that's too lenient."
            },
            {
                "term": "Fingerprinting",
                "category": "Finding Categories",
                "definition": "Information gathering techniques that identify technologies, versions, or configurations of target systems. While not vulnerabilities themselves, this information aids attackers.",
                "example": "Server version identification, framework detection, or technology stack enumeration."
            },
            {
                "term": "Exploitation",
                "category": "Finding Categories",
                "definition": "Successful exploitation of a vulnerability, demonstrating that the security issue can be actively used to compromise the system. Only reported in offensive mode.",
                "example": "Confirmed SQL injection with data extraction, successful XSS payload execution, or command injection with code execution."
            },
            {
                "term": "Compromise",
                "category": "Finding Categories",
                "definition": "Evidence that a system has been compromised or breached. This is the most serious category, indicating active security incidents.",
                "example": "Malware presence, unauthorized file modifications, or evidence of data exfiltration."
            },
            
            # Common Vulnerabilities
            {
                "term": "Cross-Site Scripting (XSS)",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. XSS attacks can steal credentials, session tokens, or perform actions on behalf of users.",
                "example": "A comment field that doesn't sanitize input, allowing an attacker to inject JavaScript that executes in other users' browsers."
            },
            {
                "term": "SQL Injection (SQLi)",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability where user input is improperly included in SQL queries, allowing attackers to manipulate database queries. Can lead to data theft, modification, or deletion.",
                "example": "A login form that constructs SQL queries by concatenating user input, allowing attackers to bypass authentication or extract data."
            },
            {
                "term": "Cross-Site Request Forgery (CSRF)",
                "category": "Common Vulnerabilities",
                "definition": "An attack that forces authenticated users to execute unwanted actions on a web application. Exploits the trust a site has in the user's browser.",
                "example": "A malicious website that makes requests to a banking site to transfer funds, using the victim's authenticated session."
            },
            {
                "term": "Server-Side Request Forgery (SSRF)",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability that allows an attacker to cause the server to make requests to unintended locations. Can be used to access internal resources, cloud metadata, or bypass firewalls.",
                "example": "An application that fetches URLs from user input without validation, allowing requests to internal IP addresses like 127.0.0.1 or cloud metadata services."
            },
            {
                "term": "XML External Entity (XXE)",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability in XML processors that allows attackers to include external entities in XML documents. Can lead to file disclosure, SSRF, or denial of service.",
                "example": "An XML parser that processes user-controlled XML without disabling external entity resolution, allowing file system access."
            },
            {
                "term": "Command Injection",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability that allows attackers to execute arbitrary operating system commands on the server. Occurs when user input is improperly included in system commands.",
                "example": "A web application that passes user input directly to shell commands without sanitization, allowing command execution."
            },
            {
                "term": "Path Traversal",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability that allows attackers to access files and directories outside the intended directory. Also known as directory traversal.",
                "example": "A file download feature that doesn't validate file paths, allowing access to sensitive files using '../' sequences."
            },
            {
                "term": "Insecure Deserialization",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability where untrusted data is deserialized, potentially allowing remote code execution, injection attacks, or privilege escalation.",
                "example": "An application that deserializes user-controlled data in Python (pickle), Java, or PHP, allowing code execution."
            },
            {
                "term": "File Upload Vulnerabilities",
                "category": "Common Vulnerabilities",
                "definition": "Security issues related to file upload functionality, including uploading malicious files, bypassing file type restrictions, or accessing uploaded files insecurely.",
                "example": "Uploading a PHP web shell disguised as an image file, or uploading files that exceed size limits causing denial of service."
            },
            {
                "term": "Insecure Direct Object Reference (IDOR)",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability where an application provides direct access to objects based on user-supplied input without proper authorization checks.",
                "example": "A URL like /api/users/123 that allows access to any user's data by changing the ID, without verifying the requester's authorization."
            },
            {
                "term": "Authentication Bypass",
                "category": "Common Vulnerabilities",
                "definition": "Vulnerabilities that allow attackers to gain unauthorized access to systems or accounts without proper authentication.",
                "example": "Weak password reset tokens, session fixation, or logic flaws in authentication mechanisms."
            },
            {
                "term": "Template Injection",
                "category": "Common Vulnerabilities",
                "definition": "A vulnerability where user input is inserted into templates and executed, allowing code execution. Includes Server-Side Template Injection (SSTI).",
                "example": "A template engine (Jinja2, Twig, FreeMarker) that processes user input, allowing remote code execution through template expressions."
            },
            
            # Technical Terms
            {
                "term": "CVE (Common Vulnerabilities and Exposures)",
                "category": "Technical Terms",
                "definition": "A standardized identifier for publicly known cybersecurity vulnerabilities. CVEs provide a common reference for security issues across different systems.",
                "example": "CVE-2021-44228 (Log4Shell) or CVE-2017-5638 (Apache Struts)."
            },
            {
                "term": "JWT (JSON Web Token)",
                "category": "Technical Terms",
                "definition": "A compact, URL-safe token format for securely transmitting information between parties. Often used for authentication and authorization.",
                "example": "A token containing user identity and permissions, signed by the server and verified on each request."
            },
            {
                "term": "GraphQL",
                "category": "Technical Terms",
                "definition": "A query language for APIs that allows clients to request exactly the data they need. Can have security implications if not properly configured.",
                "example": "A GraphQL endpoint that allows deep nested queries, potentially causing denial of service, or exposes sensitive data through introspection."
            },
            {
                "term": "WebSocket",
                "category": "Technical Terms",
                "definition": "A communication protocol that provides full-duplex communication channels over a single TCP connection. Used for real-time web applications.",
                "example": "Chat applications, live notifications, or real-time data feeds. Security concerns include authentication, data validation, and rate limiting."
            },
            {
                "term": "SSL/TLS",
                "category": "Technical Terms",
                "definition": "Cryptographic protocols designed to provide secure communication over a network. SSL is the predecessor to TLS, which is now the standard.",
                "example": "HTTPS uses TLS to encrypt data between web browsers and servers, preventing interception of sensitive information."
            },
            {
                "term": "CSP (Content Security Policy)",
                "category": "Technical Terms",
                "definition": "A security feature that helps prevent XSS attacks by allowing websites to control which resources can be loaded and executed.",
                "example": "A CSP header that restricts JavaScript execution to specific domains, preventing inline scripts and unauthorized sources."
            },
            {
                "term": "CORS (Cross-Origin Resource Sharing)",
                "category": "Technical Terms",
                "definition": "A mechanism that allows web pages to request resources from a domain different from the one serving the web page. Misconfiguration can lead to security issues.",
                "example": "An API that allows requests from any origin ('*') without proper validation, potentially exposing sensitive data."
            },
            {
                "term": "Rate Limiting",
                "category": "Technical Terms",
                "definition": "A technique to control the number of requests a user can make to an API or service within a specific time period. Helps prevent abuse and denial of service attacks.",
                "example": "Limiting login attempts to 5 per minute per IP address to prevent brute force attacks."
            },
            {
                "term": "Subdomain Enumeration",
                "category": "Technical Terms",
                "definition": "The process of discovering subdomains associated with a domain. Part of reconnaissance and can reveal additional attack surfaces.",
                "example": "Finding subdomains like admin.example.com, api.example.com, or staging.example.com that might have different security postures."
            },
            {
                "term": "Fingerprinting",
                "category": "Technical Terms",
                "definition": "The process of identifying technologies, software versions, and configurations of a target system through various techniques.",
                "example": "Identifying that a server runs Apache 2.4.41, PHP 7.4, and WordPress 5.8 through HTTP headers and response patterns."
            },
            
            # Scanning Concepts
            {
                "term": "Reconnaissance",
                "category": "Scanning Concepts",
                "definition": "The initial phase of security assessment involving information gathering about the target system, its technologies, and potential vulnerabilities.",
                "example": "Collecting information about open ports, services, software versions, and exposed endpoints before attempting exploitation."
            },
            {
                "term": "Exploitation",
                "category": "Scanning Concepts",
                "definition": "The process of actively attempting to use identified vulnerabilities to gain unauthorized access or cause harm. Only performed in offensive mode.",
                "example": "Attempting SQL injection payloads to extract database contents, or XSS payloads to execute JavaScript in user browsers."
            },
            {
                "term": "Evidence Collection",
                "category": "Scanning Concepts",
                "definition": "The process of capturing and documenting proof of vulnerabilities, including HTTP requests/responses, payloads, and system responses.",
                "example": "Recording the exact request that triggered a SQL injection, including headers, parameters, and the database error response."
            },
            {
                "term": "False Positive",
                "category": "Scanning Concepts",
                "definition": "A finding that appears to be a vulnerability but is not actually exploitable or is a misidentification. Requires manual verification.",
                "example": "A scanner flagging a parameter as vulnerable to XSS when the application properly sanitizes input on the server side."
            },
            {
                "term": "Risk Score",
                "category": "Scanning Concepts",
                "definition": "A numerical value (0-100) calculated from security findings that represents the overall security risk of the target. Higher scores indicate greater risk.",
                "example": "A score of 75/100 indicates multiple critical vulnerabilities requiring immediate attention."
            },
            {
                "term": "Attack Vector",
                "category": "Scanning Concepts",
                "definition": "A path or means by which an attacker can gain access to a system or network to deliver a malicious payload or exploit a vulnerability.",
                "example": "An exposed API endpoint with weak authentication that allows attackers to access sensitive user data."
            },
        ]
    
    @staticmethod
    def get_categories() -> List[str]:
        """Get all glossary categories."""
        terms = Glossary.get_all_terms()
        categories = sorted(set(term["category"] for term in terms))
        return categories
    
    @staticmethod
    def search_terms(query: str, category: str = None) -> List[Dict[str, Any]]:
        """Search glossary terms by query and optionally filter by category."""
        all_terms = Glossary.get_all_terms()
        query_lower = query.lower() if query else ""
        
        filtered = all_terms
        if category:
            filtered = [t for t in filtered if t["category"] == category]
        
        if query_lower:
            filtered = [
                t for t in filtered
                if query_lower in t["term"].lower() 
                or query_lower in t["definition"].lower()
                or (t.get("example") and query_lower in t["example"].lower())
            ]
        
        return filtered
