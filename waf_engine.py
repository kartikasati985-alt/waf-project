import time
from collections import defaultdict, deque

from flask import jsonify, request

from config import DEFAULT_CONFIG
from logger import WAFLogger
from rules import RISK_SCORES
from threat_detector import ThreatDetector


class WAFEngine:
    def __init__(self, app=None, config=None, logger=None):
        self.config = config or DEFAULT_CONFIG
        self.logger = logger or WAFLogger()
        self.detector = ThreatDetector(self.config.enabled_rules)
        self._rate_windows = defaultdict(deque)
        if app is not None:
            self.init_app(app)

    def _get_client_ip(self):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _rate_limited(self, ip):
        now = time.time()
        q = self._rate_windows[ip]
        while q and (now - q[0]) > self.config.rate_limit_window_seconds:
            q.popleft()
        if len(q) >= self.config.rate_limit_requests:
            return True
        q.append(now)
        return False

    def evaluate(self):
        ip = self._get_client_ip()
        if ip in self.config.whitelist_ips:
            self.logger.log_event(ip, request.method, request.full_path, "allowed", headers=dict(request.headers))
            return None

        if ip in self.config.blacklist_ips:
            findings = [{"attack_type": "blacklist", "evidence": "IP is blacklisted"}]
            self.logger.log_event(
                ip,
                request.method,
                request.full_path,
                "blocked",
                attack_type="blacklist",
                findings=findings,
                headers=dict(request.headers),
            )
            return self._blocked_response("blacklist", findings)

        if self._rate_limited(ip):
            findings = [{"attack_type": "rate_limit", "evidence": "Too many requests"}]
            self.logger.log_event(
                ip,
                request.method,
                request.full_path,
                "blocked",
                attack_type="rate_limit",
                findings=findings,
                headers=dict(request.headers),
            )
            return self._blocked_response("rate_limit", findings, status_code=429)

        body = request.get_data(as_text=True)
        findings = self.detector.detect_request(
            request.method,
            request.full_path,
            headers=dict(request.headers),
            body=body,
            form=request.form.to_dict(flat=False),
        )

        if findings:
            attack_type = findings[0]["attack_type"]
            self.logger.log_event(
                ip,
                request.method,
                request.full_path,
                "blocked",
                attack_type=attack_type,
                findings=findings,
                headers=dict(request.headers),
            )
            return self._blocked_response(attack_type, findings)

        self.logger.log_event(ip, request.method, request.full_path, "allowed", headers=dict(request.headers))
        return None

    @staticmethod
    def _blocked_response(attack_type, findings, status_code=403):
        risk_score = RISK_SCORES.get(attack_type, 5)
        return (
            jsonify(
                {
                    "status": "blocked",
                    "attack_type": attack_type,
                    "risk_score": risk_score,
                    "findings": findings,
                }
            ),
            status_code,
        )

    def init_app(self, app):
        @app.before_request
        def _waf_guard():
            if request.path.startswith("/dashboard") or request.path.startswith("/static"):
                return None
            return self.evaluate()
