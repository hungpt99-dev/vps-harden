# vps-harden — developer entry points
#
# `make test` runs exactly what CI runs (except the container integration job).
SHELL := /usr/bin/env bash
PYTHON ?= python3
ANSIBLE ?= ansible-playbook
ANSIBLE_LINT ?= ansible-lint
BATS ?= bats
VERSION := $(shell tr -d '[:space:]' < VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@printf 'vps-harden %s\n\n' "$(VERSION)"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) |
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: check
check: ## Run `install.sh check` (prerequisites, no changes)
	./install.sh check

.PHONY: lint
lint: shellcheck ansible-lint syntax ## Run every static check

.PHONY: shellcheck
shellcheck: ## ShellCheck all shell entry points
	shellcheck -x install.sh uninstall.sh scripts/*.sh tests/integration/run.sh

.PHONY: ansible-lint
ansible-lint: ## Lint roles and playbooks
	$(ANSIBLE_LINT) roles/ playbooks/

.PHONY: syntax
syntax: ## Ansible syntax check for every playbook
	@set -e; for p in playbooks/*.yml; do \
		printf '  %-28s ' "$$p"; $(ANSIBLE) --syntax-check "$$p" >/dev/null && echo ok; \
	done

.PHONY: test
test: lint test-unit ## Static checks + unit tests

.PHONY: test-unit
test-unit: test-python test-bats ## Python and Bats unit tests

.PHONY: test-python
test-python: ## pytest suites (parsers, snapshot, config contract, MCP)
	$(PYTHON) -m pytest tests/unit -q

.PHONY: test-bats
test-bats: ## CLI, configuration and snapshot Bats suites
	$(BATS) tests/unit/*.bats

.PHONY: test-integration
test-integration: ## Disposable Ubuntu 24.04 container (requires Docker)
	./tests/integration/run.sh

.PHONY: test-molecule
test-molecule: ## Molecule scenario for the baseline role (requires Docker)
	cd tests && molecule test

.PHONY: docs
docs: ## List documentation
	@ls -1 docs/*.md | sed 's/^/  /'

.PHONY: install
install: ## Install the `vps-harden` command into /usr/local/bin
	install -m 0755 install.sh /usr/local/bin/vps-harden
	@printf 'Installed. Run: sudo vps-harden check\n'

.PHONY: clean
clean: ## Remove local test artifacts
	rm -rf .pytest_cache tests/molecule/*/.molecule reports/*.md
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

.PHONY: version
version: ## Print the version
	@echo "$(VERSION)"
