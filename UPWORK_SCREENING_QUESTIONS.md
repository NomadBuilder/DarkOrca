# Screening Questions for Security Scanner Review & Enhancement

Use these questions to evaluate candidates for the SecurityScan code review and enhancement task.

---

## Required Screening Questions

### 1. Technical Background

**Q: Please describe your experience with Python security testing tools. Have you worked with tools like WPScan, Nuclei, SQLMap, or Nmap? Please provide specific examples.**

**Expected Answer:**
- Experience with at least 2-3 of these tools
- Specific examples of use cases
- Understanding of how these tools work
- Bonus: Experience with Python tool development/integration

**Red Flags:**
- Generic answers without specifics
- No experience with any of these tools
- Only theoretical knowledge

---

### 2. WordPress Security Knowledge

**Q: What are the most common WordPress vulnerabilities you've encountered? Describe a specific WordPress security test you've performed (plugin vulnerability, authentication bypass, file inclusion, etc.).**

**Expected Answer:**
- Mentions common WP vulnerabilities (XSS, SQL injection, file upload, plugin exploits, etc.)
- Specific example of testing performed
- Understanding of WordPress architecture (plugins, themes, REST API, etc.)
- Knowledge of WordPress-specific attack vectors

**Red Flags:**
- Vague or generic answers
- No specific examples
- Only mentions basic vulnerabilities without WP context

---

### 3. False Positive Reduction

**Q: How would you identify and fix false positives in a security scanner? Give an example of a common false positive (e.g., public API endpoints flagged as vulnerabilities, login pages flagged as accessible admin panels) and how you would fix it.**

**Expected Answer:**
- Understands that false positives are a major issue in security scanning
- Can explain validation techniques (baseline comparison, impact testing, context-aware detection)
- Provides specific example of false positive and solution
- Mentions importance of evidence/proof before flagging vulnerabilities

**Red Flags:**
- Doesn't understand false positive concept
- Suggests flagging everything and letting users filter
- No understanding of validation techniques

---

### 4. Code Quality & Testing

**Q: When reviewing security scanner code, what code quality issues would you look for? How would you ensure the scanner handles errors gracefully (e.g., when a target is unreachable, scanner crashes, or returns unexpected output)?**

**Expected Answer:**
- Mentions error handling (try/except, graceful degradation)
- Code organization and maintainability
- Testing approach (unit tests, integration tests)
- Logging and debugging capabilities
- Input validation and sanitization
- Timeout handling

**Red Flags:**
- No mention of error handling
- Focus only on functionality, not code quality
- No testing experience

---

### 5. WordPress Offensive Testing

**Q: If you were to enhance WordPress offensive testing capabilities, what specific attack vectors would you add? Please name at least 3 WordPress-specific vulnerabilities you would test for and briefly explain how.**

**Expected Answer:**
- Plugin/theme exploitation
- WordPress REST API security
- Authentication/authorization bypasses
- File upload vulnerabilities
- Database error-based SQL injection (WP-specific)
- XMLRPC vulnerabilities
- Media library security
- Gutenberg/XSS vulnerabilities
- Specific understanding of WordPress attack surfaces

**Red Flags:**
- Generic web vulnerabilities without WP context
- Less than 3 specific examples
- No understanding of WordPress-specific attack vectors

---

### 6. Practical Experience

**Q: Have you previously worked on security scanner tools or vulnerability detection systems? If yes, describe the project and your contributions. If no, describe a security testing project you've completed.**

**Expected Answer:**
- Specific project examples
- Clear description of their role and contributions
- Understanding of security testing workflows
- Experience with either building tools or extensive use of tools

**Red Flags:**
- No relevant experience
- Only academic/theoretical knowledge
- Cannot provide specific examples

---

### 7. Python Code Review

**Q: Review this code snippet and identify issues:**

```python
def test_api_endpoint(url):
    response = requests.get(url)
    if response.status_code == 200:
        return {"vulnerable": True, "severity": "HIGH"}
    return {"vulnerable": False}
```

**What security issues and code quality problems do you see?**

**Expected Answer Should Mention:**
- No error handling (what if request fails?)
- No timeout handling
- Assumes 200 = vulnerable (false positive issue)
- Doesn't check what the 200 response contains
- No input validation
- No logging
- Hardcoded severity without context
- Should test actual impact before flagging

**Red Flags:**
- Misses obvious issues
- Suggests minimal changes
- Doesn't understand the false positive problem

---

## Optional Advanced Questions

### 8. Tool Integration Experience

**Q: The tool integrates multiple scanners (WPScan, Nuclei, Nmap). What challenges would you expect when integrating output from different scanners with different formats? How would you handle this?**

**Expected Answer:**
- Understands parsing challenges
- Mentions normalization of output
- Handling different severity levels across tools
- Dealing with conflicting results
- Timeout/performance considerations

---

### 9. Rate Limiting & OPSEC

**Q: When performing security scans, how do you handle rate limiting, detection, and operational security? What techniques would you implement to make scans less detectable?**

**Expected Answer:**
- User-Agent rotation
- Request throttling/delays
- Respect for rate limits (429 handling)
- IP rotation considerations
- Stealth scanning techniques
- Understanding of WAF/CDN detection

---

### 10. Reporting & Evidence

**Q: When a scanner reports a vulnerability, what information should be included to make it useful and actionable? How do you distinguish between a suspected vulnerability and a confirmed one?**

**Expected Answer:**
- Evidence/proof requirements
- Request/response examples
- Severity justification
- Remediation guidance
- Confidence scores
- False positive awareness
- Need for manual verification

---

## Scoring Guide

**Excellent Candidate (Proceed):**
- Answers 5+ required questions well
- Specific examples and experience
- Demonstrates deep understanding
- Addresses false positive concerns
- Shows WordPress security expertise

**Good Candidate (Consider):**
- Answers 4 required questions well
- Some experience shown
- Understands key concepts
- May need guidance on some areas

**Weak Candidate (Skip):**
- Answers less than 3 required questions well
- Vague or generic answers
- No relevant experience
- Doesn't understand false positives
- Limited WordPress knowledge

---

## Follow-up Questions Based on Answers

If candidate mentions:
- **WPScan experience** → "How would you enhance WPScan integration beyond basic enumeration?"
- **False positives** → "What validation techniques have you used to reduce false positives?"
- **WordPress plugins** → "How would you test for plugin vulnerabilities beyond enumeration?"
- **Code quality** → "What's your approach to refactoring security scanner code?"

---

## Red Flags to Watch For

❌ **Avoid candidates who:**
- Give generic, copy-paste answers
- Can't provide specific examples
- Focus only on exploitation, not detection accuracy
- Don't understand false positives are a problem
- Have only academic knowledge, no practical experience
- Can't explain their previous work clearly
- Suggest flagging everything and letting users filter
- Don't mention error handling or code quality
- Have no WordPress security experience
- Can't identify issues in code review example

✅ **Look for candidates who:**
- Provide specific, detailed examples
- Understand false positives and validation
- Have practical security testing experience
- Can identify code quality issues
- Show WordPress security expertise
- Demonstrate understanding of security tool development
- Mention error handling and robustness
- Show attention to detail

---

## Quick Pre-Screening (Use in Upwork Messages)

Before sending full questions, ask these 3 quick questions to filter candidates:

1. **"Have you used WPScan, Nuclei, or similar security scanners? If yes, briefly describe your experience."**

2. **"What's the biggest challenge with security scanner false positives, and how do you address it?"**

3. **"Have you performed WordPress security testing? Please name 2 WordPress-specific vulnerabilities you've tested for."**

Only proceed with candidates who answer these well.

---

## Notes

- These questions test practical knowledge, not just theory
- Good candidates should be able to provide specific examples
- WordPress security knowledge is critical for this project
- Understanding false positives is essential
- Code quality awareness is important

**Recommended:** Ask all 7 required questions, then use optional questions if needed for clarification.

