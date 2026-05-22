.PHONY: help setup py-sync ansible-deps lint test bootstrap add-nads health

# macOS fork-safety workaround for Ansible workers on Python 3.13+
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export no_proxy=*
VAULT_PASS_FILE ?= /tmp/.vault_pass

help:
	@echo "Targets:"
	@echo "  setup         - Install python deps (uv) and Ansible collections"
	@echo "  py-sync       - uv sync the python package"
	@echo "  ansible-deps  - Install Ansible collections"
	@echo "  lint          - Ruff + ansible-lint"
	@echo "  test          - Run pytest"
	@echo "  bootstrap     - Run ISE bootstrap playbook"
	@echo "  add-nads      - Add switches as Network Devices in ISE"
	@echo "  health        - Quick ISE health check (python)"

setup: py-sync ansible-deps

py-sync:
	cd python && uv sync

ansible-deps:
	ansible-galaxy collection install -r ansible/requirements.yml

lint:
	cd python && uv run ruff check .
	ansible-lint ansible/playbooks/ || true

test:
	cd python && uv run pytest

bootstrap:
	cd ansible && ansible-playbook playbooks/ise_bootstrap.yml --vault-password-file $(VAULT_PASS_FILE)

add-nads:
	cd ansible && ansible-playbook playbooks/ise_network_devices.yml --vault-password-file $(VAULT_PASS_FILE)

health:
	cd python && uv run python -m scripts.health_check
