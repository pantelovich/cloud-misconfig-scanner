from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single misconfiguration finding returned by any check."""

    service: str
    resource: str
    status: str  # "FAIL", "WARN", "PASS"
    message: str
    detail: Optional[dict] = field(default=None)

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "resource": self.resource,
            "status": self.status,
            "message": self.message,
            "detail": self.detail,
        }
