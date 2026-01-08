# layer2_pipeline/validator.py

import re
from typing import Dict, Any


class Validator:
    CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"

    def validate(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        errors = []

        if "asset" not in parsed_data:
            errors.append("Missing asset information")

        for vuln in parsed_data.get("vulnerabilities", []):
            cve = vuln.get("cve")
            if cve and not re.match(self.CVE_PATTERN, cve):
                errors.append(f"Invalid CVE format: {cve}")

        return {"is_valid": len(errors) == 0, "errors": errors}
