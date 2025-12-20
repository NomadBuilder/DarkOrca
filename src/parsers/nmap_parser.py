"""Parser for Nmap XML/JSON output."""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

from ..models.finding import Finding, FindingSeverity, FindingCategory


class NmapParser:
    """Parse Nmap XML/JSON output into Finding objects."""
    
    @staticmethod
    def parse(xml_output: Optional[str] = None, json_output: Optional[str] = None) -> List[Finding]:
        """
        Parse Nmap output (XML or JSON).
        
        Args:
            xml_output: Nmap XML output
            json_output: Nmap JSON output
            
        Returns:
            List of findings
        """
        if json_output:
            return NmapParser._parse_json(json_output)
        elif xml_output:
            return NmapParser._parse_xml(xml_output)
        else:
            raise ValueError("Either xml_output or json_output must be provided")
    
    @staticmethod
    def _parse_json(json_output: str) -> List[Finding]:
        """Parse Nmap JSON output."""
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid Nmap JSON: {e}")
        
        findings = []
        
        if "nmaprun" in data:
            scan_data = data["nmaprun"]
        else:
            scan_data = data
        
        hosts = scan_data.get("host", [])
        if not isinstance(hosts, list):
            hosts = [hosts]
        
        for host in hosts:
            host_findings = NmapParser._parse_host(host)
            findings.extend(host_findings)
        
        return findings
    
    @staticmethod
    def _parse_xml(xml_output: str) -> List[Finding]:
        """Parse Nmap XML output."""
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            raise ValueError(f"Invalid Nmap XML: {e}")
        
        findings = []
        
        for host in root.findall("host"):
            host_data = NmapParser._xml_host_to_dict(host)
            host_findings = NmapParser._parse_host(host_data)
            findings.extend(host_findings)
        
        return findings
    
    @staticmethod
    def _xml_host_to_dict(host_elem: ET.Element) -> Dict[str, Any]:
        """Convert XML host element to dictionary."""
        host_data = {}
        
        # Addresses
        addresses = []
        for addr in host_elem.findall("address"):
            addresses.append({
                "addr": addr.get("addr"),
                "addrtype": addr.get("addrtype"),
            })
        if addresses:
            host_data["address"] = addresses
        
        # Ports
        ports = []
        for port in host_elem.findall(".//port"):
            port_data = {
                "portid": port.get("portid"),
                "protocol": port.get("protocol"),
            }
            
            state = port.find("state")
            if state is not None:
                port_data["state"] = {
                    "state": state.get("state"),
                    "reason": state.get("reason"),
                }
            
            service = port.find("service")
            if service is not None:
                port_data["service"] = {
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "extrainfo": service.get("extrainfo"),
                }
            
            script = port.find("script")
            if script is not None:
                port_data["script"] = {
                    "id": script.get("id"),
                    "output": script.text,
                }
            
            ports.append(port_data)
        
        if ports:
            host_data["ports"] = {"port": ports}
        
        return host_data
    
    @staticmethod
    def _parse_host(host: Dict[str, Any]) -> List[Finding]:
        """Parse findings from a single host."""
        findings = []
        
        addresses = host.get("address", [])
        if not isinstance(addresses, list):
            addresses = [addresses]
        
        host_ip = addresses[0].get("addr") if addresses else "unknown"
        
        ports_data = host.get("ports", {})
        ports = ports_data.get("port", []) if isinstance(ports_data, dict) else []
        if not isinstance(ports, list):
            ports = [ports]
        
        # Analyze open ports
        open_ports = [p for p in ports if p.get("state", {}).get("state") == "open"]
        
        if len(open_ports) > 20:
            findings.append(Finding(
                title="Excessive Open Ports",
                description=f"Host {host_ip} has {len(open_ports)} open ports, indicating a large attack surface.",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.MISCONFIGURATION,
                source_scanner="nmap",
                source_id="excessive_ports",
                remediation="Review and close unnecessary ports. Implement firewall rules to restrict access.",
                metadata={"port_count": len(open_ports)},
            ))
        
        # Common web ports that are expected to be open (not security findings)
        expected_web_ports = {"80", "443", "8080", "8443"}
        
        # Analyze services
        for port in open_ports:
            port_id = port.get("portid", "unknown")
            service = port.get("service", {})
            service_name = service.get("name", "unknown")
            product = service.get("product", "")
            version = service.get("version", "")
            extrainfo = service.get("extrainfo", "")
            
            # Skip expected web ports (HTTP/HTTPS) - these are normal
            if port_id in expected_web_ports and service_name.lower() in ["http", "https", "http-proxy", "ssl/http"]:
                continue  # Don't report standard web ports as findings
            
            # Clean up service info - remove "None" and malformed data
            service_parts = []
            if product and product.lower() not in ["none", "unknown", ""]:
                service_parts.append(product)
            if version and version.lower() not in ["none", "unknown", ""]:
                service_parts.append(version)
            if extrainfo and extrainfo.lower() not in ["none", "unknown", ""]:
                service_parts.append(extrainfo)
            
            service_info = " ".join(service_parts).strip() if service_parts else service_name
            
            # Only report if we have meaningful service information or it's a non-standard port
            if service_name != "unknown" or product or port_id not in expected_web_ports:
                # Skip if service info is just "None" or empty
                if service_info.lower() in ["none", "unknown", ""] and port_id in expected_web_ports:
                    continue
                    
                findings.append(Finding(
                    title=f"Open Port {port_id} - {service_name}",
                    description=f"Port {port_id} is open and running {service_info or service_name}. This exposes a network service that could be targeted by attackers." if service_info else f"Port {port_id} is open and running {service_name}.",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.EXPOSED_ENDPOINT,
                    source_scanner="nmap",
                    source_id=f"open_port_{port_id}",
                    url=f"{host_ip}:{port_id}",
                    remediation=f"Review if port {port_id} needs to be publicly accessible. Implement firewall rules to restrict access if not required.",
                    metadata={
                        "port": port_id,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                ))
            
            # Check for version disclosure (more specific finding)
            # Skip version disclosure for standard web ports and when version is "None" or empty
            if version and version.lower() not in ["none", "unknown", ""] and port_id not in expected_web_ports:
                findings.append(Finding(
                    title=f"Service Version Disclosure on Port {port_id}",
                    description=f"Port {port_id} ({service_name}) exposes version information: {product} {version}. This aids attackers in identifying vulnerabilities.",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner="nmap",
                    source_id=f"version_disclosure_{port_id}",
                    url=f"{host_ip}:{port_id}",
                    remediation=f"Disable or minimize version disclosure for {service_name} on port {port_id}.",
                    metadata={
                        "port": port_id,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                ))
            
            # Check for potentially dangerous services
            dangerous_services = {
                "ftp": FindingSeverity.MEDIUM,
                "telnet": FindingSeverity.HIGH,
                "rlogin": FindingSeverity.HIGH,
                "rsh": FindingSeverity.HIGH,
                "vnc": FindingSeverity.MEDIUM,
            }
            
            service_lower = service_name.lower()
            for dangerous, sev in dangerous_services.items():
                if dangerous in service_lower:
                    findings.append(Finding(
                        title=f"Insecure Service Detected: {service_name}",
                        description=f"Port {port_id} is running {service_name}, which typically uses unencrypted communication and may be vulnerable to interception.",
                        severity=sev,
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner="nmap",
                        source_id=f"insecure_service_{port_id}",
                        url=f"{host_ip}:{port_id}",
                        remediation=f"Disable {service_name} or replace with a secure alternative (e.g., SSH instead of Telnet).",
                        metadata={"port": port_id, "service": service_name},
                    ))
                    break
        
        return findings

