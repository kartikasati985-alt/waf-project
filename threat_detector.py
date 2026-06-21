from urllib.parse import parse_qs, unquote, urlparse

from rules import ATTACK_PATTERNS


class ThreatDetector:
    def __init__(self, enabled_rules=None):
        self.enabled_rules = enabled_rules or {}

    def _enabled(self, rule_name):
        return self.enabled_rules.get(rule_name, True)

    @staticmethod
    def _flatten(values):
        if values is None:
            return []
        if isinstance(values, (list, tuple, set)):
            return [str(v) for v in values]
        if isinstance(values, dict):
            output = []
            for key, value in values.items():
                output.append(str(key))
                if isinstance(value, (list, tuple, set)):
                    output.extend(str(v) for v in value)
                else:
                    output.append(str(value))
            return output
        return [str(values)]

    def detect_text(self, text):
        matches = []
        decoded = unquote(str(text or ""))
        for attack_type, patterns in ATTACK_PATTERNS.items():
            if not self._enabled(attack_type):
                continue
            for pattern in patterns:
                hit = pattern.search(decoded)
                if hit:
                    matches.append(
                        {
                            "attack_type": attack_type,
                            "pattern": pattern.pattern,
                            "evidence": hit.group(0)[:200],
                        }
                    )
                    break
        return matches

    def detect_request(self, method, full_path, headers=None, body=None, form=None):
        findings = []
        parsed = urlparse(full_path or "")
        query_params = parse_qs(parsed.query)

        sources = []
        sources.extend(self._flatten(parsed.path))
        sources.extend(self._flatten(query_params))
        sources.extend(self._flatten(form or {}))
        sources.extend(self._flatten(headers or {}))
        sources.extend(self._flatten(body))

        for source in sources:
            findings.extend(self.detect_text(source))

        if self._enabled("csrf") and str(method).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            headers = headers or {}
            has_token = bool(headers.get("X-CSRF-Token") or headers.get("X-Csrf-Token"))
            same_origin = bool(headers.get("Origin") or headers.get("Referer"))
            if not has_token and not same_origin:
                findings.append(
                    {
                        "attack_type": "csrf",
                        "pattern": "missing_csrf_token",
                        "evidence": "Mutating request without CSRF token or origin/referer",
                    }
                )

        unique = []
        seen = set()
        for finding in findings:
            key = (finding["attack_type"], finding["pattern"])
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique
