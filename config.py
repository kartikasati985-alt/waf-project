from dataclasses import dataclass, field


@dataclass
class WAFConfig:
    enabled_rules: dict = field(
        default_factory=lambda: {
            "sql_injection": True,
            "xss": True,
            "csrf": True,
            "path_traversal": True,
            "file_inclusion": True,
            "command_injection": True,
            "xxe": True,
        }
    )
    whitelist_ips: set = field(default_factory=set)
    blacklist_ips: set = field(default_factory=set)
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60


DEFAULT_CONFIG = WAFConfig()
