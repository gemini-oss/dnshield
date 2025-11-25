#!/usr/bin/env python3
"""Apply signing identity configuration across the DNShield build."""

from __future__ import annotations

import argparse
import json
import plistlib
import sys
from io import BytesIO
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY_DIR = REPO_ROOT / "config" / "identities"
XCCONFIG_PATH = REPO_ROOT / "dnshield" / "Configurations" / "Identity.xcconfig"
HEADER_PATH = REPO_ROOT / "dnshield" / "Common" / "DNIdentity.h"
ACTIVE_ID_PATH = IDENTITY_DIR / ".active"
LAUNCH_DAEMON_PATH = (
    REPO_ROOT / "resources" / "package" / "LaunchDaemons" / "com.dnshield.daemon.plist"
)


REQUIRED_KEYS = {
    "display_name",
    "bundle_prefix",
    "domain_name",
    "app_bundle_id",
    "extension_bundle_id",
    "daemon_bundle_id",
    "preference_domain",
    "app_group",
    "mach_service_name",
    "team_id",
    "developer_id_application",
    "developer_id_installer",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply a signing identity")
    parser.add_argument(
        "--identity",
        default="default",
        help="Identity name under config/identities (without .json)",
    )
    return parser.parse_args()


def load_identity(name: str) -> dict:
    path = IDENTITY_DIR / f"{name}.json"
    if not path.is_file():
        raise SystemExit(f"Identity '{name}' not found at {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise SystemExit(
            f"Identity '{name}' missing required keys: {', '.join(missing)}"
        )

    profiles = data.get("provisioning_profiles", {})
    for required in ("app", "extension"):
        if required not in profiles:
            raise SystemExit(
                f"Identity '{name}' missing provisioning profile for '{required}'"
            )

    data.setdefault("identity", name)
    data["provisioning_profiles"] = profiles
    data.setdefault("extension_code_sign_identity", data["developer_id_application"])
    data.setdefault("extension_product_name", data["extension_bundle_id"])
    data.setdefault(
        "extension_system_extension_id",
        f"{data['extension_bundle_id']}.systemextension",
    )
    data.setdefault("extension_xpc_identifier", f"{data['extension_bundle_id']}.xpc")

    return data


def write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def write_bytes_if_changed(path: Path, payload: bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.read_bytes() if path.exists() else None
    if current == payload:
        return False
    path.write_bytes(payload)
    return True


def escape_objc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_xcconfig(identity: dict) -> str:
    profiles = identity["provisioning_profiles"]
    lines = [
        "// This file is auto-generated. Run make identity to update.",
        f"DN_IDENTITY_NAME = {identity['identity']}",
        f"DN_DISPLAY_NAME = {identity['display_name']}",
        f"DN_BUNDLE_PREFIX = {identity['bundle_prefix']}",
        f"DN_DOMAIN_NAME = {identity['domain_name']}",
        f"DN_TEAM_ID = {identity['team_id']}",
        "",
        f"DN_APP_BUNDLE_ID = {identity['app_bundle_id']}",
        f"DN_EXTENSION_BUNDLE_ID = {identity['extension_bundle_id']}",
        f"DN_DAEMON_BUNDLE_ID = {identity['daemon_bundle_id']}",
        f"DN_PREFERENCE_DOMAIN = {identity['preference_domain']}",
        f"DN_APP_GROUP_IDENTIFIER = {identity['app_group']}",
        f"DN_MACH_SERVICE_NAME = {identity['mach_service_name']}",
        f"DN_EXTENSION_PRODUCT_NAME = {identity['extension_product_name']}",
        f"DN_EXTENSION_SYSTEM_EXTENSION_ID = {identity['extension_system_extension_id']}",
        f"DN_EXTENSION_XPC_IDENTIFIER = {identity['extension_xpc_identifier']}",
        "",
        f"DN_APP_CODE_SIGN_IDENTITY = {identity['developer_id_application']}",
        f"DN_EXTENSION_CODE_SIGN_IDENTITY = {identity['extension_code_sign_identity']}",
        f"DN_INSTALLER_CODE_SIGN_IDENTITY = {identity['developer_id_installer']}",
        "",
        f"DN_APP_PROVISIONING_PROFILE = {profiles['app']}",
        f"DN_EXTENSION_PROVISIONING_PROFILE = {profiles['extension']}",
        "",
    ]
    return "\n".join(lines)


def build_header(identity: dict) -> str:
    template = "\n".join(
        [
            "// This file is auto-generated. Run make identity to update.",
            "",
            "#pragma once",
            "",
            f"#define DN_IDENTITY_NAME @\"{escape_objc(identity['identity'])}\"",
            f"#define DN_IDENTITY_DISPLAY_NAME @\"{escape_objc(identity['display_name'])}\"",
            f"#define DN_IDENTITY_BUNDLE_PREFIX @\"{escape_objc(identity['bundle_prefix'])}\"",
            f"#define DN_IDENTITY_DOMAIN_NAME @\"{escape_objc(identity['domain_name'])}\"",
            "",
            f"#define DN_IDENTITY_APP_BUNDLE_ID @\"{escape_objc(identity['app_bundle_id'])}\"",
            f"#define DN_IDENTITY_EXTENSION_BUNDLE_ID @\"{escape_objc(identity['extension_bundle_id'])}\"",
            f"#define DN_IDENTITY_DAEMON_BUNDLE_ID @\"{escape_objc(identity['daemon_bundle_id'])}\"",
            f"#define DN_IDENTITY_PREFERENCE_DOMAIN @\"{escape_objc(identity['preference_domain'])}\"",
            f"#define DN_IDENTITY_APP_GROUP @\"{escape_objc(identity['app_group'])}\"",
            f"#define DN_IDENTITY_MACH_SERVICE @\"{escape_objc(identity['mach_service_name'])}\"",
            f"#define DN_IDENTITY_EXTENSION_PRODUCT_NAME @\"{escape_objc(identity['extension_product_name'])}\"",
            f"#define DN_IDENTITY_EXTENSION_SYSTEM_EXTENSION_ID @\"{escape_objc(identity['extension_system_extension_id'])}\"",
            f"#define DN_IDENTITY_EXTENSION_XPC_IDENTIFIER @\"{escape_objc(identity['extension_xpc_identifier'])}\"",
            "",
            f"#define DN_IDENTITY_TEAM_IDENTIFIER @\"{escape_objc(identity['team_id'])}\"",
        ]
    )
    return template + "\n"


def update_launch_daemon(identity: dict) -> bool:
    if not LAUNCH_DAEMON_PATH.exists():
        return False

    plist_data = plistlib.loads(LAUNCH_DAEMON_PATH.read_bytes())
    plist_data["Label"] = identity["daemon_bundle_id"]
    plist_data["MachServices"] = {identity["mach_service_name"]: True}
    plist_data["AssociatedBundleIdentifiers"] = [
        identity["app_bundle_id"],
        identity["extension_bundle_id"],
    ]

    buffer = BytesIO()
    plistlib.dump(plist_data, buffer)
    return write_bytes_if_changed(LAUNCH_DAEMON_PATH, buffer.getvalue())


def main() -> None:
    args = parse_args()
    identity = load_identity(args.identity)

    xc_written = write_if_changed(XCCONFIG_PATH, build_xcconfig(identity))
    header_written = write_if_changed(HEADER_PATH, build_header(identity))
    daemon_written = update_launch_daemon(identity)
    write_if_changed(ACTIVE_ID_PATH, identity["identity"] + "\n")

    if xc_written or header_written or daemon_written:
        print(f"Applied signing identity '{identity['identity']}'")
    else:
        print(f"Signing identity '{identity['identity']}' already applied")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
