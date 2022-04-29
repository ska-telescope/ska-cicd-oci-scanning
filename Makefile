COMBINED_INVENTORY=../combined_inventory

.DEFAULT_GOAL := help

# define overides for above variables in here
-include PrivateRules.mak

lint:  ## Lint check playbooks and roles
	yamllint -d "{extends: relaxed, rules: {line-length: {max: 256}}}" \
			-f parsable \
			playbooks/roles/* \
			playbooks/*.yml \
			| yamllint-junit -o linting-yamllint.xml;
	ansible-lint --nocolor playbooks/roles/* \playbooks/*.yml -p | tee ansible-lint.txt;
	ansible-lint-junit ansible-lint.txt -o linting-ansible.xml
	flake8 --format junit-xml playbooks/roles/* --output-file linting-flake.xml

set_inventory:  ## Combines the inventory from the parent folder for scanning
	mkdir -p $(COMBINED_INVENTORY)
	rm -f $(COMBINED_INVENTORY)/*
	cp ../inventory_* $(COMBINED_INVENTORY)/
	rm -f $(COMBINED_INVENTORY)/*.save $(COMBINED_INVENTORY)/*.backup

scan: set_inventory  ## Scans the images running on the inventory
	ansible-playbook -i $(COMBINED_INVENTORY) playbooks/oci_scan.yml

help:  ## Show this help.
	@echo "make targets:"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ": .*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""; echo "make vars (+defaults):"
	@grep -E '^[0-9a-zA-Z_-]+ \?=.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = " \\?= "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'