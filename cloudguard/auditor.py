"""
ScorpionXploit CloudGuard - AWS & Azure Security Posture Analyzer
Author: Aditya Sharma (scorpionxploit)
License: Apache-2.0
"""
from typing import List, Dict, Any

class CloudGuardAuditor:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def audit_iam_policy(self, policy_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect")
            action = stmt.get("Action")
            resource = stmt.get("Resource")

            if effect == "Allow":
                if action == "*" or (isinstance(action, list) and "*" in action):
                    if resource == "*" or (isinstance(resource, list) and "*" in resource):
                        self.findings.append({
                            "rule_id": "SX-AWS-IAM-001-WILDCARD_PERMISSIONS",
                            "severity": "CRITICAL",
                            "title": "Full administrative wildcard policy detected",
                            "remediation": "Restrict policy actions to least privilege required."
                        })
        return self.findings

    def audit_security_group(self, sg_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sensitive_ports = {22: "SSH", 3389: "RDP", 23: "Telnet", 3306: "MySQL"}
        for rule in sg_rules:
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")
            cidrs = rule.get("CidrIp", [])
            if isinstance(cidrs, str):
                cidrs = [cidrs]

            if "0.0.0.0/0" in cidrs:
                for port, name in sensitive_ports.items():
                    if from_port and to_port and from_port <= port <= to_port:
                        self.findings.append({
                            "rule_id": f"SX-AWS-SG-PORT_{port}_PUBLIC",
                            "severity": "HIGH",
                            "title": f"Unrestricted 0.0.0.0/0 ingress on {name} (Port {port})",
                            "remediation": "Restrict CIDR to specific bastion host or VPN range."
                        })
        return self.findings
