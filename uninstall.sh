#!/usr/bin/env bash
#
# Thin wrapper: uninstall is implemented as a playbook so that it is idempotent
# and auditable. See playbooks/uninstall.yml.
set -Eeuo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/install.sh" uninstall "$@"
