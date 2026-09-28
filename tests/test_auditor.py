"""
Tests for CloudGuard Auditor
"""
from cloudguard.auditor import CloudGuardAuditor

def test_flag_wildcard_iam_action():
    auditor = CloudGuardAuditor()
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = auditor.audit_iam_policy(sample_policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "WILDCARD_PERMISSIONS" in findings[0]["rule_id"]

def test_detect_public_security_group_ingress():
    auditor = CloudGuardAuditor()
    sample_rules = [
        {"FromPort": 22, "ToPort": 22, "CidrIp": ["0.0.0.0/0"]},
        {"FromPort": 443, "ToPort": 443, "CidrIp": ["0.0.0.0/0"]}
    ]
    findings = auditor.audit_security_group(sample_rules)
    rule_ids = [f["rule_id"] for f in findings]
    assert "SX-AWS-SG-PORT_22_PUBLIC" in rule_ids
