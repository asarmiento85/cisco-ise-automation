.PHONY: help setup py-sync ansible-deps lint test bootstrap add-nads health

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
	cd ansible && ansible-playbook playbooks/ise_bootstrap.yml --ask-vault-pass

add-nads:
	cd ansible && ansible-playbook playbooks/ise_network_devices.yml --ask-vault-pass

health:
	cd python && uv run python -m scripts.health_check
