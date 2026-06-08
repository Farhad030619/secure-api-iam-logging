import os
import logging
from logging.handlers import RotatingFileHandler

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Define audit log formatter
audit_formatter = logging.Formatter(
    '[%(asctime)s] SECURITY_AUDIT | IP: %(client_ip)s | User: %(username)s | Event: %(event_type)s | %(message)s'
)

# Set up audit log handler (rotating log file, 10MB limit, keep 5 backups)
audit_handler = RotatingFileHandler(
    filename=os.path.join("logs", "audit.log"),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)
audit_handler.setFormatter(audit_formatter)

# Create and configure the audit logger
audit_logger = logging.getLogger("security_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)
# Prevent audit logs from propagating to the root logger (console) if we want it isolated
audit_logger.propagate = False

def log_security_event(event_type: str, username: str, client_ip: str, details: str):
    """
    Helper function to log a security audit event.
    Common event types:
    - REGISTER_SUCCESS
    - REGISTER_FAILED
    - LOGIN_SUCCESS
    - FAILED_LOGIN_ATTEMPT
    - UNAUTHORIZED_ADMIN_ACCESS
    """
    audit_logger.info(
        details,
        extra={
            "client_ip": client_ip,
            "username": username,
            "event_type": event_type
        }
    )
