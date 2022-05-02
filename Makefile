INVENTORY_PATH ?= ..
SLACK_VULN_WEBHOOK_URL ?=

.DEFAULT_GOAL := help

# define overides for above variables in here
-include PrivateRules.mak

install:  ## Install dependencies
	poetry export -f requirements.txt -o requirements.txt --without-hashes
	pip3 install -r requirements.txt

lint:  ## Lint check playbooks and roles
	yamllint -d "{extends: relaxed, rules: {line-length: {max: 256}}}" \
			-f parsable \
			playbooks/roles/* \
			playbooks/*.yml \
			| yamllint-junit -o linting-yamllint.xml;
	ansible-lint --nocolor playbooks/roles/* \playbooks/*.yml -p | tee ansible-lint.txt;
	ansible-lint-junit ansible-lint.txt -o linting-ansible.xml
	flake8 playbooks/roles/* --output-file linting-flake.xml --format junit-xml

set_inventory:  ## Combines the inventory from the parent folder for scanning
	mkdir -p $(INVENTORY_PATH)/combined_inventory
	rm -f $(INVENTORY_PATH)/combined_inventory/*
	cp $(INVENTORY_PATH)/inventory_* $(INVENTORY_PATH)/combined_inventory/
	rm -f $(INVENTORY_PATH)/combined_inventory/*.save $(INVENTORY_PATH)/combined_inventory/*.backup

scan: set_inventory  ## Scans the images running on the inventory
	ansible-playbook -i $(INVENTORY_PATH)/combined_inventory \
		-e "slack_vuln_webhook_url=$(SLACK_VULN_WEBHOOK_URL)" \
		playbooks/oci_scan.yml

help:  ## Show this help.
	@echo "make targets:"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ": .*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""; echo "make vars (+defaults):"
	@grep -E '^[0-9a-zA-Z_-]+ \?=.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = " \\?= "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'