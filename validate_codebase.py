#!/usr/bin/env python3
"""
Comprehensive Codebase Validation Script
Checks both static code analysis AND runtime behavior patterns
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Tuple

class CodebaseValidator:
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.passed = []
        
    def log_issue(self, category: str, message: str, severity: str = "error"):
        """Log an issue found during validation"""
        self.issues.append({
            'category': category,
            'message': message,
            'severity': severity
        })
        
    def log_warning(self, category: str, message: str):
        """Log a warning"""
        self.warnings.append({
            'category': category,
            'message': message
        })
        
    def log_pass(self, category: str, message: str):
        """Log a passed check"""
        self.passed.append({
            'category': category,
            'message': message
        })
    
    def check_javascript_event_handlers(self, js_content: str, file_path: str):
        """Check JavaScript event handlers for proper attachment and timing"""
        print("\n🔍 Checking JavaScript Event Handlers...")
        
        # Check for form submission handlers
        form_handlers = list(re.finditer(r"getElementById\(['\"]scanForm['\"]\)", js_content))
        if not form_handlers:
            self.log_issue("Event Handlers", "No form submission handler found for scanForm", "critical")
            return
        
        for match in form_handlers:
            start_pos = match.start()
            # Get context around the handler
            context_start = max(0, start_pos - 200)
            context_end = min(len(js_content), start_pos + 500)
            context = js_content[context_start:context_end]
            
            # Check if handler is wrapped in DOMContentLoaded
            handler_before = js_content[:start_pos]
            if 'DOMContentLoaded' in handler_before[-500:] or 'document.readyState' in handler_before[-500:]:
                self.log_pass("Event Handlers", "Form handler is wrapped in DOM ready check")
            else:
                self.log_issue("Event Handlers", 
                    "Form handler may not wait for DOM ready - could fail if script loads early", 
                    "critical")
            
            # Check if preventDefault is called
            handler_code = js_content[start_pos:start_pos+1000]
            if 'preventDefault()' in handler_code:
                self.log_pass("Event Handlers", "preventDefault() is called in form handler")
            else:
                self.log_issue("Event Handlers", "preventDefault() not found in form handler", "critical")
            
            # Check if stopPropagation is called
            if 'stopPropagation()' in handler_code:
                self.log_pass("Event Handlers", "stopPropagation() is called")
            else:
                self.log_warning("Event Handlers", "stopPropagation() not found - other handlers might interfere")
            
            # Check if return false is present
            if 'return false' in handler_code:
                self.log_pass("Event Handlers", "return false is present")
            else:
                self.log_warning("Event Handlers", "return false not found - form might still submit")
    
    def check_dom_readiness(self, js_content: str):
        """Check if DOM-dependent code waits for DOM to be ready"""
        print("\n🔍 Checking DOM Readiness...")
        
        # Find all getElementById calls
        get_element_calls = list(re.finditer(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_content))
        
        # Check if they're in DOMContentLoaded or similar
        module_level_elements = []
        for match in get_element_calls:
            element_id = match.group(1)
            pos = match.start()
            
            # Check if this is at module level (not in a function that's called after DOM ready)
            # Look backwards for function declaration or DOMContentLoaded
            before_code = js_content[:pos]
            
            # Check if it's inside a function that's called after DOM ready
            in_dom_ready_function = False
            # Look for DOMContentLoaded in the last 1000 chars before this
            if 'DOMContentLoaded' in before_code[-1000:]:
                # Check if we're inside that handler
                dom_ready_pos = before_code.rfind('DOMContentLoaded')
                # Simple check: if we're after DOMContentLoaded and before next function, we're likely in it
                in_dom_ready_function = True
            
            # Check if it's in a function that's called after setup
            if 'setupFormHandler' in before_code[-500:] or 'DOMContentLoaded' in before_code[-500:]:
                in_dom_ready_function = True
            
            if not in_dom_ready_function and element_id in ['scanForm', 'targetInput', 'scanMode', 'startScanBtn']:
                # Check if it's at module level (not in a function)
                # Look for function declaration before this
                func_match = re.search(r'function\s+\w+\s*\([^)]*\)\s*\{', before_code[-500:])
                if not func_match:
                    module_level_elements.append((element_id, pos))
        
        if module_level_elements:
            for element_id, pos in module_level_elements[:5]:  # Show first 5
                line_num = js_content[:pos].count('\n') + 1
                self.log_issue("DOM Readiness", 
                    f"getElementById('{element_id}') at line {line_num} may run before DOM is ready",
                    "warning")
        else:
            self.log_pass("DOM Readiness", "All critical DOM element access is properly guarded")
    
    def check_form_attributes(self, html_content: str):
        """Check form tag for proper attributes"""
        print("\n🔍 Checking Form Attributes...")
        
        form_match = re.search(r'<form[^>]*id=["\']scanForm["\'][^>]*>', html_content)
        if not form_match:
            self.log_issue("Form Attributes", "scanForm not found in HTML", "critical")
            return
        
        form_tag = form_match.group(0)
        
        # Check for onsubmit
        if 'onsubmit=' in form_tag:
            if 'return false' in form_tag or 'preventDefault' in form_tag:
                self.log_pass("Form Attributes", "Form has onsubmit handler that prevents default")
            else:
                self.log_warning("Form Attributes", "Form has onsubmit but may not prevent default")
        else:
            self.log_warning("Form Attributes", "Form missing onsubmit='return false;' failsafe")
        
        # Check for action attribute (should not have one for SPA)
        if 'action=' in form_tag:
            self.log_issue("Form Attributes", "Form has action attribute - may cause page reload", "warning")
        else:
            self.log_pass("Form Attributes", "Form has no action attribute (good for SPA)")
        
        # Check for method attribute
        if 'method=' in form_tag:
            self.log_warning("Form Attributes", "Form has method attribute - may conflict with JavaScript handler")
    
    def check_api_endpoint_usage(self, js_content: str, py_content: str):
        """Check if frontend API calls match backend routes"""
        print("\n🔍 Checking API Endpoint Usage...")
        
        # Extract frontend API calls
        api_calls = set()
        for match in re.finditer(r"fetch\(['\"]([^'\"]+)['\"]", js_content):
            url = match.group(1)
            if url.startswith('/api/'):
                api_calls.add(url)
        
        # Also check template literals
        for match in re.finditer(r"fetch\(`([^`]+)`", js_content):
            url = match.group(1)
            # Extract the base path (before ${variables})
            base_path = url.split('${')[0] if '${' in url else url
            if base_path.startswith('/api/'):
                api_calls.add(base_path.split('${')[0] + '...')  # Mark as template
        
        # Extract backend routes
        backend_routes = set()
        for match in re.finditer(r"@app\.(?:route|get|post)\(['\"]([^'\"]+)['\"]", py_content):
            route = match.group(1)
            backend_routes.add(route)
        
        # Check each frontend call
        for api_call in api_calls:
            if '...' in api_call:  # Template literal
                base = api_call.replace('...', '')
                # Check if any backend route matches the pattern
                found = any(base in route or route.replace('<scan_id>', '').replace('<shareable_id>', '') in base 
                           for route in backend_routes)
                if found:
                    self.log_pass("API Endpoints", f"Template API call {api_call} has matching backend route")
                else:
                    self.log_issue("API Endpoints", f"Template API call {api_call} may not have backend route", "warning")
            else:
                # Exact match or pattern match
                found = False
                for route in backend_routes:
                    # Handle Flask route patterns
                    route_pattern = route.replace('<scan_id>', '[^/]+').replace('<shareable_id>', '[^/]+')
                    if re.match(route_pattern + '$', api_call) or api_call == route:
                        found = True
                        break
                
                if found:
                    self.log_pass("API Endpoints", f"API call {api_call} has matching backend route")
                else:
                    self.log_issue("API Endpoints", f"API call {api_call} has no matching backend route", "error")
    
    def check_error_handling(self, js_content: str):
        """Check for proper error handling in async code"""
        print("\n🔍 Checking Error Handling...")
        
        # Find all fetch calls
        fetch_calls = list(re.finditer(r'fetch\([^)]+\)', js_content))
        
        for i, match in enumerate(fetch_calls):
            pos = match.end()
            # Check if there's a try-catch or .catch() after this
            after_code = js_content[pos:pos+500]
            
            if 'catch' in after_code or '.catch(' in after_code:
                self.log_pass("Error Handling", f"Fetch call {i+1} has error handling")
            else:
                # Check if it's in a try block
                before_code = js_content[:match.start()]
                try_blocks = before_code.count('try {')
                catch_blocks = before_code.count('catch')
                if try_blocks > catch_blocks:
                    # Might be in a try block
                    self.log_warning("Error Handling", f"Fetch call {i+1} may be in try block but verify catch exists")
                else:
                    self.log_issue("Error Handling", f"Fetch call {i+1} has no error handling", "warning")
    
    def check_null_safety(self, js_content: str):
        """Check for null safety when accessing DOM elements"""
        print("\n🔍 Checking Null Safety...")
        
        # Find getElementById calls
        get_element_calls = list(re.finditer(r"(\w+)\s*=\s*getElementById\(['\"]([^'\"]+)['\"]\)", js_content))
        
        for match in get_element_calls:
            var_name = match.group(1)
            element_id = match.group(2)
            pos = match.end()
            
            # Check if there's a null check after this
            after_code = js_content[pos:pos+200]
            
            if f'if ({var_name})' in after_code or f'if (!{var_name})' in after_code or f'{var_name}?' in after_code:
                self.log_pass("Null Safety", f"getElementById('{element_id}') has null check")
            else:
                # Check if it's used immediately (which would throw if null)
                usage = re.search(rf'\b{var_name}\.[a-zA-Z]', after_code[:100])
                if usage:
                    self.log_issue("Null Safety", 
                        f"getElementById('{element_id}') result used without null check", 
                        "warning")
    
    def check_duplicate_listeners(self, js_content: str):
        """Check for potential duplicate event listeners"""
        print("\n🔍 Checking for Duplicate Listeners...")
        
        # Count addEventListener calls for the same element
        listeners = {}
        for match in re.finditer(r"getElementById\(['\"]([^'\"]+)['\"]\)[^.]*\.addEventListener\(['\"]([^'\"]+)['\"]", js_content):
            element_id = match.group(1)
            event_type = match.group(2)
            key = f"{element_id}.{event_type}"
            if key not in listeners:
                listeners[key] = []
            listeners[key].append(match.start())
        
        duplicates = {k: v for k, v in listeners.items() if len(v) > 1}
        if duplicates:
            for key, positions in duplicates.items():
                element_id, event_type = key.split('.')
                self.log_issue("Duplicate Listeners", 
                    f"Multiple addEventListener('{event_type}') for '{element_id}' - may cause duplicate handlers",
                    "warning")
        else:
            self.log_pass("Duplicate Listeners", "No duplicate event listeners detected")
    
    def check_python_syntax(self, file_path: str):
        """Check Python file syntax"""
        print(f"\n🔍 Checking Python Syntax: {file_path}...")
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'py_compile', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.log_pass("Python Syntax", f"{file_path} syntax is valid")
            else:
                self.log_issue("Python Syntax", f"{file_path} has syntax errors: {result.stderr[:200]}", "error")
        except Exception as e:
            self.log_warning("Python Syntax", f"Could not validate {file_path}: {e}")
    
    def check_variable_scoping(self, js_content: str):
        """Check for variable scoping issues"""
        print("\n🔍 Checking Variable Scoping...")
        
        # Find module-level variable declarations
        lines = js_content.split('\n')
        module_vars = {}
        
        for i, line in enumerate(lines, 1):
            # Match let/var/const at start of line (module level)
            match = re.match(r'^(let|var|const)\s+(\w+)', line.strip())
            if match:
                var_name = match.group(2)
                if var_name not in ['i', 'j', 'k', 'x', 'y', 'z']:  # Skip loop vars
                    if var_name not in module_vars:
                        module_vars[var_name] = []
                    module_vars[var_name].append(i)
        
        # Check for duplicates
        duplicates = {name: locs for name, locs in module_vars.items() if len(locs) > 1}
        if duplicates:
            for name, locs in list(duplicates.items())[:5]:
                self.log_issue("Variable Scoping", 
                    f"Variable '{name}' declared multiple times at module level (lines {locs})",
                    "error")
        else:
            self.log_pass("Variable Scoping", "No duplicate module-level variable declarations")
    
    def check_function_duplicates(self, js_content: str):
        """Check for duplicate function declarations"""
        print("\n🔍 Checking Function Declarations...")
        
        func_declarations = {}
        for match in re.finditer(r'^\s*function\s+(\w+)\s*\(', js_content, re.MULTILINE):
            func_name = match.group(1)
            line_num = js_content[:match.start()].count('\n') + 1
            if func_name not in func_declarations:
                func_declarations[func_name] = []
            func_declarations[func_name].append(line_num)
        
        duplicates = {name: locs for name, locs in func_declarations.items() if len(locs) > 1}
        if duplicates:
            for name, locs in duplicates.items():
                self.log_issue("Function Declarations", 
                    f"Function '{name}' declared multiple times (lines {locs})", 
                    "error")
        else:
            self.log_pass("Function Declarations", "No duplicate function declarations")
    
    def check_critical_dom_elements(self, js_content: str, html_content: str):
        """Check if critical DOM elements exist in HTML"""
        print("\n🔍 Checking Critical DOM Elements...")
        
        # Find all getElementById calls
        js_elements = set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_content))
        
        # Find all id attributes in HTML
        html_elements = set(re.findall(r'id=["\']([^"\']+)["\']', html_content))
        
        # Critical elements that must exist
        critical_elements = ['scanForm', 'targetInput', 'scanMode', 'startScanBtn', 
                           'scanProgress', 'scanResults', 'riskScore', 'findingsCount']
        
        for elem_id in critical_elements:
            if elem_id in js_elements:
                if elem_id in html_elements:
                    self.log_pass("DOM Elements", f"Critical element '{elem_id}' exists in HTML")
                else:
                    self.log_issue("DOM Elements", 
                        f"Critical element '{elem_id}' used in JS but not found in HTML", 
                        "error")
    
    def run_validation(self):
        """Run all validation checks"""
        print("=" * 60)
        print("COMPREHENSIVE CODEBASE VALIDATION")
        print("=" * 60)
        
        # Read files
        js_path = Path('static/js/app.js')
        html_path = Path('templates/index.html')
        py_path = Path('web_app.py')
        
        if not js_path.exists():
            print(f"❌ {js_path} not found")
            return
        
        with open(js_path, 'r') as f:
            js_content = f.read()
        
        with open(html_path, 'r') as f:
            html_content = f.read()
        
        with open(py_path, 'r') as f:
            py_content = f.read()
        
        # Run all checks
        self.check_javascript_event_handlers(js_content, str(js_path))
        self.check_dom_readiness(js_content)
        self.check_form_attributes(html_content)
        self.check_api_endpoint_usage(js_content, py_content)
        self.check_error_handling(js_content)
        self.check_null_safety(js_content)
        self.check_duplicate_listeners(js_content)
        self.check_variable_scoping(js_content)
        self.check_function_duplicates(js_content)
        self.check_critical_dom_elements(js_content, html_content)
        self.check_python_syntax(str(py_path))
        
        # Print summary
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"\n✅ Passed: {len(self.passed)}")
        for check in self.passed[:10]:  # Show first 10
            print(f"   ✓ {check['category']}: {check['message']}")
        
        print(f"\n⚠️  Warnings: {len(self.warnings)}")
        for warning in self.warnings:
            print(f"   ⚠ {warning['category']}: {warning['message']}")
        
        print(f"\n❌ Issues: {len(self.issues)}")
        critical = [i for i in self.issues if i['severity'] == 'critical' or i['severity'] == 'error']
        warnings_only = [i for i in self.issues if i['severity'] == 'warning']
        
        if critical:
            print(f"\n   Critical/Errors ({len(critical)}):")
            for issue in critical:
                print(f"   ✗ {issue['category']}: {issue['message']}")
        
        if warnings_only:
            print(f"\n   Warnings ({len(warnings_only)}):")
            for issue in warnings_only[:10]:
                print(f"   ⚠ {issue['category']}: {issue['message']}")
        
        print(f"\n{'='*60}")
        if not critical:
            print("✅ No critical issues found!")
        else:
            print(f"❌ {len(critical)} critical issue(s) need attention")
        print(f"{'='*60}")
        
        return len(critical) == 0

if __name__ == '__main__':
    validator = CodebaseValidator()
    success = validator.run_validation()
    sys.exit(0 if success else 1)

