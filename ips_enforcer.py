from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
import ipaddress

from config import FIREWALL_BACKEND, IPS_MODE, IPS_VERIFY_TIMEOUT_SEC

BLOCK_ACTIONS = {"BLOCK", "ISOLATE"}
UNBLOCK_ACTIONS = {"UNBLOCK", "UNISOLATE", "WHITELIST"}


@dataclass
class EnforcementResult:
    ips_mode: str
    enforcement_method: str
    firewall_backend: str
    verification_status: str
    real_block_applied: bool
    database_only: bool
    inline_block: bool
    gateway_block: bool
    local_block: bool
    rule_exists: bool
    command_status: str
    message: str
    error_reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(int(IPS_VERIFY_TIMEOUT_SEC), 1),
            check=False,
        )
        output = ((completed.stdout or "") + (completed.stderr or "")).strip()
        return completed.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


def _is_admin() -> bool:
    if not _is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _windows_firewall_enabled() -> tuple[bool, str]:
    if not _is_windows():
        return False, "not running on Windows"
    ok, output = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if not ok:
        return False, output or "failed to query Windows Firewall state"
    enabled = "State" in output and "ON" in output.upper()
    return enabled, output


def _backend_available(backend: str) -> tuple[bool, str]:
    if backend == "windows":
        if not _is_windows():
            return False, "Windows firewall backend selected on a non-Windows host"
        if not shutil.which("netsh"):
            return False, "netsh was not found in PATH"
        firewall_enabled, details = _windows_firewall_enabled()
        if not firewall_enabled:
            return False, details or "Windows Firewall appears to be disabled"
        return True, "Windows Firewall backend available"
    if backend == "iptables":
        return bool(shutil.which("iptables")), "iptables found" if shutil.which("iptables") else "iptables not found"
    if backend == "nftables":
        return bool(shutil.which("nft")), "nft found" if shutil.which("nft") else "nft not found"
    return False, "no firewall backend selected"


def _select_backend() -> str:
    if IPS_MODE == "database":
        return "none"
    if FIREWALL_BACKEND != "auto":
        return FIREWALL_BACKEND
    if _is_windows():
        return "windows"
    if shutil.which("nft"):
        return "nftables"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def _chain_for_mode() -> str:
    return "FORWARD" if IPS_MODE in {"gateway_firewall", "inline"} else "INPUT"


def _method_for_mode(backend: str) -> str:
    if IPS_MODE == "database":
        return "database"
    if IPS_MODE == "local_firewall":
        return f"local_firewall:{backend}"
    if IPS_MODE == "gateway_firewall":
        return f"gateway_firewall:{backend}"
    if IPS_MODE == "inline":
        return f"inline:{backend}"
    return "database"


def _empty_result(message: str) -> EnforcementResult:
    return EnforcementResult(
        ips_mode=IPS_MODE,
        enforcement_method="database",
        firewall_backend="none",
        verification_status="database_only",
        real_block_applied=False,
        database_only=True,
        inline_block=False,
        gateway_block=False,
        local_block=False,
        rule_exists=False,
        command_status="skipped",
        message=message,
        error_reason=message,
    )


def _windows_rule_name(ip: str) -> str:
    return f"FusionStrikeAI_BLOCK_{ip}"


def firewall_rule_name(ip: str) -> str:
    backend = _select_backend()
    if backend == "windows":
        return _windows_rule_name(ip)
    return f"FusionStrikeAI_BLOCK_{ip}"


def verify_firewall_rule(ip: str) -> dict:
    target = str(ip or "").strip()
    backend = _select_backend()
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return {
            "rule_name": firewall_rule_name(target),
            "rule_exists": False,
            "verification_status": "failed",
            "enforcement_method": _method_for_mode(backend),
            "firewall_backend": backend,
            "message": "firewall verification requires a valid IP address target",
        }

    if backend == "windows":
        exists = _windows_verify(target)
    elif backend == "iptables":
        exists = _iptables_verify(target)
    elif backend == "nftables":
        exists = _nft_verify(target)
    else:
        exists = False

    return {
        "rule_name": firewall_rule_name(target),
        "rule_exists": exists,
        "verification_status": "verified" if exists else "failed",
        "enforcement_method": _method_for_mode(backend),
        "firewall_backend": backend,
        "message": "firewall block rule exists" if exists else "firewall block rule was not found",
    }


def _windows_apply(ip: str, remove: bool) -> tuple[bool, bool, str]:
    name = _windows_rule_name(ip)
    if remove:
        delete_ok, output = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        exists = _windows_verify(ip)
        if not delete_ok:
            return False, exists, output or "windows firewall rule delete failed"
        if not exists:
            return True, False, output or "windows firewall rule removed"
        return False, True, output or "windows firewall rule still exists"

    ok, output = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ])
    exists = _windows_verify(ip)
    return ok and exists, exists, output or "windows firewall block rule applied"


def _windows_verify(ip: str) -> bool:
    ok, output = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={_windows_rule_name(ip)}"])
    return ok and ip in output


def _iptables_apply(ip: str, remove: bool) -> tuple[bool, bool, str]:
    chain = _chain_for_mode()
    if remove:
        _run(["iptables", "-D", chain, "-s", ip, "-j", "DROP"])
        exists = _iptables_verify(ip)
        return not exists, exists, "iptables rule removed" if not exists else "iptables rule still exists"

    if not _iptables_verify(ip):
        ok, output = _run(["iptables", "-A", chain, "-s", ip, "-j", "DROP"])
        if not ok:
            return False, False, output
    exists = _iptables_verify(ip)
    return exists, exists, f"iptables {chain} drop rule active"


def _iptables_verify(ip: str) -> bool:
    chain = _chain_for_mode()
    ok, _ = _run(["iptables", "-C", chain, "-s", ip, "-j", "DROP"])
    return ok


def _nft_apply(ip: str, remove: bool) -> tuple[bool, bool, str]:
    hook = "forward" if IPS_MODE in {"gateway_firewall", "inline"} else "input"
    chain = f"fusion_{hook}"
    comment = f"FusionStrikeAI_BLOCK_{ip}"

    _run(["nft", "add", "table", "inet", "fusion_strike"])
    _run([
        "nft", "add", "chain", "inet", "fusion_strike", chain,
        "{", "type", "filter", "hook", hook, "priority", "0", ";", "policy", "accept", ";", "}",
    ])

    if remove:
        # nft has no stable handle here; flush all Fusion rules for a simple demo-safe reset.
        _run(["nft", "flush", "chain", "inet", "fusion_strike", chain])
        exists = _nft_verify(ip)
        return not exists, exists, "nftables fusion chain flushed" if not exists else "nftables rule still exists"

    if not _nft_verify(ip):
        ok, output = _run([
            "nft", "add", "rule", "inet", "fusion_strike", chain,
            "ip", "saddr", ip, "drop", "comment", comment,
        ])
        if not ok:
            return False, False, output
    exists = _nft_verify(ip)
    return exists, exists, f"nftables {hook} drop rule active"


def _nft_verify(ip: str) -> bool:
    ok, output = _run(["nft", "list", "ruleset"])
    return ok and f"FusionStrikeAI_BLOCK_{ip}" in output


def enforce(action: str, target: str) -> dict:
    action_upper = str(action or "").upper()
    target = str(target or "").strip()

    if not target:
        return _empty_result("no target supplied").to_dict()
    try:
        ipaddress.ip_address(target)
    except ValueError:
        result = _empty_result("firewall enforcement requires a valid IP address target")
        result.verification_status = "failed"
        result.command_status = "failed"
        return result.to_dict()
    if IPS_MODE == "database":
        return _empty_result("IPS_MODE=database: dashboard/database state only, no firewall rule applied").to_dict()

    backend = _select_backend()
    if backend == "none":
        result = _empty_result("no supported firewall backend found")
        result.ips_mode = IPS_MODE
        result.enforcement_method = _method_for_mode(backend)
        result.verification_status = "failed"
        result.command_status = "failed"
        return result.to_dict()

    available, availability_message = _backend_available(backend)
    if not available:
        return EnforcementResult(
            ips_mode=IPS_MODE,
            enforcement_method=_method_for_mode(backend),
            firewall_backend=backend,
            verification_status="failed",
            real_block_applied=False,
            database_only=False,
            inline_block=False,
            gateway_block=False,
            local_block=False,
            rule_exists=False,
            command_status="failed",
            message=availability_message,
            error_reason=availability_message,
        ).to_dict()

    remove = action_upper in UNBLOCK_ACTIONS
    should_block = action_upper in BLOCK_ACTIONS
    if not remove and not should_block:
        return _empty_result(f"action {action_upper} does not require firewall enforcement").to_dict()

    if backend == "windows":
        ok, exists, message = _windows_apply(target, remove)
    elif backend == "iptables":
        ok, exists, message = _iptables_apply(target, remove)
    elif backend == "nftables":
        ok, exists, message = _nft_apply(target, remove)
    else:
        ok, exists, message = False, False, "unsupported firewall backend"

    real_block = (not remove) and ok and exists
    verification_status = "verified" if ((remove and not exists and ok) or real_block) else "failed"
    return EnforcementResult(
        ips_mode=IPS_MODE,
        enforcement_method=_method_for_mode(backend),
        firewall_backend=backend,
        verification_status=verification_status,
        real_block_applied=real_block,
        database_only=False,
        inline_block=real_block and IPS_MODE == "inline",
        gateway_block=real_block and IPS_MODE == "gateway_firewall",
        local_block=real_block and IPS_MODE == "local_firewall",
        rule_exists=exists,
        command_status="success" if ok else "failed",
        message=message,
        error_reason="" if ok else message,
    ).to_dict()


def current_enforcement_profile() -> dict:
    backend = _select_backend()
    available, availability_message = _backend_available(backend)
    admin = _is_admin() if backend == "windows" else False
    firewall_enabled, firewall_status_message = _windows_firewall_enabled() if backend == "windows" else (available, availability_message)
    real_capable = (
        IPS_MODE in {"local_firewall", "gateway_firewall", "inline"}
        and backend != "none"
        and available
        and (backend != "windows" or admin)
    )
    return {
        "ips_mode": IPS_MODE,
        "firewall_backend": backend,
        "enforcement_method": _method_for_mode(backend),
        "admin_privileges": admin,
        "firewall_available": available,
        "firewall_enabled": firewall_enabled,
        "firewall_status_message": firewall_status_message,
        "backend_status_message": availability_message,
        "real_prevention_capable": real_capable,
        "database_only": IPS_MODE == "database",
        "inline_capable": IPS_MODE == "inline",
        "gateway_capable": IPS_MODE == "gateway_firewall",
    }


def firewall_self_test(test_ip: str = "203.0.113.250") -> dict:
    backend = _select_backend()
    profile = current_enforcement_profile()
    if backend != "windows":
        return {
            "success": False,
            "stage": "backend",
            "test_ip": test_ip,
            "profile": profile,
            "error": f"self-test endpoint currently supports the Windows backend, got {backend}",
        }

    add_ok, add_exists, add_message = _windows_apply(test_ip, remove=False)
    verify_after_add = _windows_verify(test_ip)
    remove_ok, remove_exists, remove_message = _windows_apply(test_ip, remove=True)
    verify_after_remove = _windows_verify(test_ip)

    success = bool(add_ok and add_exists and verify_after_add and remove_ok and not remove_exists and not verify_after_remove)
    error = ""
    if not success:
        error = remove_message if verify_after_remove else add_message

    return {
        "success": success,
        "stage": "complete" if success else "failed",
        "test_ip": test_ip,
        "profile": profile,
        "add": {
            "ok": add_ok,
            "rule_exists": add_exists,
            "verified": verify_after_add,
            "message": add_message,
            "command": "netsh advfirewall firewall add rule",
        },
        "remove": {
            "ok": remove_ok,
            "rule_exists": remove_exists,
            "verified_absent": not verify_after_remove,
            "message": remove_message,
            "command": "netsh advfirewall firewall delete rule",
        },
        "error": error,
    }
