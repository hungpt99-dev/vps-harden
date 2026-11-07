"""Configuration contract test.

The user-facing schema (config/defaults.yml), the mapping layer
(group_vars/all.yml) and the role defaults must not drift apart. Drift looks
like: a new option appears in the docs but is never passed to a role, or a role
default is changed while the documented default stays behind.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = ROOT / "config" / "defaults.yml"
# group_vars must sit next to the playbooks that use them: Ansible resolves
# group_vars relative to the inventory file and the playbook, not the repo root.
MAPPING = ROOT / "playbooks" / "group_vars" / "all.yml"
ROLES = ROOT / "roles"

# Paths intentionally not exposed through group_vars:
#   backup_dir        read by scripts/backup.sh (vh_config_value), not a role var
#   ufw.extra_rules   merged into ufw.rules by playbooks/tasks/load_config.yml
#   ufw.auto_allow_ssh, ufw.allow_tailscale
#                     same: they build the derived rule list
UNMAPPED_OK = {
    "backup_dir",
    "ufw.extra_rules",
    "ufw.auto_allow_ssh",
    "ufw.allow_tailscale",
}

ROLE_FOR_PREFIX = {
    "common_": "common",
    "ssh_": "ssh_hardening",
    "ufw_": "ufw",
    "fail2ban_": "fail2ban",
    "crowdsec_": "crowdsec",
    "unattended_": "unattended_upgrades",
    "tailscale_": "tailscale",
    "docker_": "docker",
    "hermes_": "hermes_agent",
    "monitoring_": "monitoring",
    "logging_": "logging",
    "backup_": "backup",
    "audit_": "security_audit",
}

MAPPING_RE = re.compile(r"^([a-z][a-z0-9_]*):\s*\"?\{\{\s*vps_harden\.([a-z0-9_.]+)\s*\}\}\"?\s*$")


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def leaf_paths(node, prefix=""):
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                yield from leaf_paths(value, child)
            else:
                yield child


def get_path(document: dict, dotted: str):
    node = document
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


_MISSING = object()


def mapping() -> dict[str, str]:
    """Parse `var: "{{ vps_harden.a.b }}"` lines from group_vars/all.yml."""
    result: dict[str, str] = {}
    for line in MAPPING.read_text(encoding="utf-8").splitlines():
        match = MAPPING_RE.match(line.strip())
        if match:
            result[match.group(1)] = match.group(2)
    return result


def role_defaults(role: str) -> dict:
    path = ROLES / role / "defaults" / "main.yml"
    return load_yaml(path) if path.is_file() else {}


@pytest.fixture(scope="module")
def defaults() -> dict:
    return load_yaml(DEFAULTS)["vps_harden"]


@pytest.fixture(scope="module")
def mapped() -> dict[str, str]:
    return mapping()


def test_mapping_is_not_empty(mapped: dict[str, str]) -> None:
    assert len(mapped) > 50, "mapping layer looks truncated"


def test_every_mapped_path_exists_in_defaults(defaults: dict, mapped: dict[str, str]) -> None:
    missing = [
        f"{variable} -> vps_harden.{path}"
        for variable, path in mapped.items()
        if get_path(defaults, path) is _MISSING
    ]
    assert not missing, f"mapped keys missing from config/defaults.yml: {missing}"


def test_every_default_is_mapped_or_allowlisted(defaults: dict, mapped: dict[str, str]) -> None:
    paths = set(mapped.values())
    unmapped = [
        path for path in leaf_paths(defaults) if path not in paths and path not in UNMAPPED_OK
    ]
    assert not unmapped, f"these options are documented but never reach a role: {unmapped}"


def test_role_defaults_match_the_documented_defaults(
    defaults: dict, mapped: dict[str, str]
) -> None:
    mismatches = []
    for variable, path in mapped.items():
        role = next((r for p, r in ROLE_FOR_PREFIX.items() if variable.startswith(p)), None)
        if role is None:
            continue
        role_vars = role_defaults(role)
        if variable not in role_vars:
            continue
        documented = get_path(defaults, path)
        actual = role_vars[variable]
        if isinstance(actual, str) and actual.startswith("{{"):
            continue  # computed default, e.g. ufw_ssh_port
        if documented != actual:
            mismatches.append(f"{variable}: docs={documented!r} role={actual!r} ({role})")
    assert not mismatches, "\n".join(mismatches)


def test_every_role_has_a_defaults_file() -> None:
    missing = [
        path.parent.parent.name
        for path in ROLES.glob("*/tasks/main.yml")
        if not (path.parent.parent / "defaults" / "main.yml").is_file()
    ]
    assert not missing, f"roles without defaults: {missing}"


def test_every_role_gates_on_the_phase_variable() -> None:
    """A role that ignores vh_phase runs during `install` as well as `configure`."""
    offenders = []
    for main in ROLES.glob("*/tasks/main.yml"):
        text = main.read_text(encoding="utf-8")
        if "vh_phase" not in text:
            offenders.append(main.parent.parent.name)
    assert not offenders, f"roles not gated on vh_phase: {offenders}"


def test_roles_with_an_install_file_import_it() -> None:
    """A role with tasks/install.yml that never imports it installs nothing."""
    offenders = []
    for role_dir in ROLES.iterdir():
        if not (role_dir / "tasks" / "install.yml").is_file():
            continue
        main = role_dir / "tasks" / "main.yml"
        text = main.read_text(encoding="utf-8")
        if "install.yml" not in text:
            offenders.append(role_dir.name)
    assert not offenders, f"roles with an unimported install.yml: {offenders}"


def _walk_tasks(node):
    """Yield every task mapping, descending into block/rescue/always."""
    if isinstance(node, list):
        for item in node:
            yield from _walk_tasks(item)
    elif isinstance(node, dict):
        if "block" in node or "rescue" in node or "always" in node:
            for key in ("block", "rescue", "always"):
                yield from _walk_tasks(node.get(key))
            return
        yield node


def test_every_notify_matches_a_handler() -> None:
    """Handlers are matched by name, case-sensitively: a typo is a runtime error."""
    offenders = []
    for role_dir in ROLES.iterdir():
        if not (role_dir / "tasks").is_dir():
            continue
        handler_names: set[str] = set()
        handlers_file = role_dir / "handlers" / "main.yml"
        if handlers_file.is_file():
            for task in _walk_tasks(yaml.safe_load(handlers_file.read_text()) or []):
                if "name" in task:
                    handler_names.add(task["name"])
                for topic in task.get("listen") or []:
                    handler_names.add(topic)
        for task_file in (role_dir / "tasks").glob("*.yml"):
            for task in _walk_tasks(yaml.safe_load(task_file.read_text()) or []):
                notify = task.get("notify")
                if not notify:
                    continue
                targets = notify if isinstance(notify, list) else [notify]
                for target in targets:
                    if "{{" in str(target):
                        continue
                    if target not in handler_names:
                        offenders.append(f"{role_dir.name}: '{target}' ({task_file.name})")
    assert not offenders, f"notify targets with no handler: {offenders}"


def test_ssh_dropin_name_is_a_managed_path() -> None:
    """The role's drop-in name and the snapshot inventory must not drift."""
    role_defaults = load_yaml(ROLES / "ssh_hardening" / "defaults" / "main.yml")
    name = role_defaults["ssh_dropin_name"]
    owned = set(load_yaml(ROOT / "config" / "managed_paths.yml")["vh_managed"]["owned_files"])
    assert f"/etc/ssh/sshd_config.d/{name}" in owned


def test_playbook_pre_tasks_run_even_when_tags_are_used() -> None:
    """`--tags ssh` must not skip config loading and the pre-change snapshot."""
    offenders = []
    for playbook in (ROOT / "playbooks").glob("*.yml"):
        plays = yaml.safe_load(playbook.read_text(encoding="utf-8")) or []
        for play in plays:
            if not isinstance(play, dict):
                continue
            for task in play.get("pre_tasks", []) or []:
                imports = [
                    value
                    for key, value in task.items()
                    if key.endswith("import_tasks") or key.endswith("include_tasks")
                ]
                if not imports:
                    continue
                tags = task.get("tags") or []
                if "always" not in tags:
                    offenders.append(f"{playbook.name}: {imports[0]}")
    assert not offenders, f"pre_tasks without the 'always' tag: {offenders}"


def test_managed_paths_file_parses_and_is_absolute() -> None:
    data = load_yaml(ROOT / "config" / "managed_paths.yml")["vh_managed"]
    for section in ("owned_files", "modified_files"):
        assert data[section], f"{section} must not be empty"
        for path in data[section]:
            assert path.startswith("/"), f"non-absolute managed path: {path}"
            assert ".." not in path, f"traversal in managed path: {path}"


def test_every_role_template_destination_is_a_managed_path() -> None:
    """A generated system file that is not in the inventory cannot be rolled back."""
    inventory = load_yaml(ROOT / "config" / "managed_paths.yml")["vh_managed"]
    managed = set(inventory["owned_files"]) | set(inventory["modified_files"])
    prefixes = ("/etc/", "/usr/", "/opt/", "/var/")
    unlisted = []
    for task_file in ROLES.glob("*/tasks/*.yml"):
        for line in task_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("dest:"):
                continue
            dest = stripped.split("dest:", 1)[1].strip().strip('"')
            if not dest.startswith(prefixes):
                continue  # downloads to /tmp, temporary renders
            if "{{" in dest:
                continue  # dynamic path (e.g. systemd unit name), reviewed manually
            if dest not in managed:
                unlisted.append(f"{task_file.relative_to(ROOT)} -> {dest}")
    assert not unlisted, f"templates writing unmanaged paths: {unlisted}"
