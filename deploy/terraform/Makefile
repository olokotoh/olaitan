# Olaitan evaluation cluster.
#
# The cluster is cattle and it is billed by the hour, so the workflow is
# `make up` for a campaign, `make stop` between sessions (you keep the
# disks and pay only for them), and `make down` when the campaign is
# finished and the artefacts are safe in runs/.

# Overridable, and no longer defaulted to one developer's AWS profile and
# key file. `default` is the profile every AWS install has; KEY is derived
# from the key pair name so the two stay consistent.
PROFILE ?= $(if $(AWS_PROFILE),$(AWS_PROFILE),default)
REGION  ?= $(if $(AWS_REGION),$(AWS_REGION),us-east-1)
KEY_NAME ?= olaitan-e2e
KEY     ?= ~/.ssh/$(KEY_NAME).pem
AWS     := aws --profile $(PROFILE) --region $(REGION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	| awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: init
init: ## terraform init
	terraform init

.PHONY: plan
plan: ## Show what would change
	terraform plan

.PHONY: up
up: ## Create the cluster nodes (does NOT run kubeadm init)
	terraform apply
	@echo
	@echo "Nodes created. Bootstrap runs on first boot; a reboot happens only if the kernel changed."
	@echo "Run 'make wait' before touching kubeadm."

.PHONY: wait
wait: ## Block until every node has finished bootstrapping and rebooted
	@set -e; \
	for ip in $$(terraform output -json ssh | python3 -c 'import json,sys; [print(v.split("@")[1]) for v in json.load(sys.stdin).values()]'); do \
	  printf "waiting for %s " "$$ip"; \
	  for i in $$(seq 1 80); do \
	    k=$$(ssh -i $(KEY) -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes \
	         ubuntu@$$ip 'test -f /var/lib/olaitan-bootstrap.done && uname -r' 2>/dev/null || true); \
	    case "$$k" in 6.8*) printf " ready (kernel %s)\n" "$$k"; break ;; esac; \
	    printf "."; sleep 15; \
	    if [ "$$i" = 80 ]; then printf " TIMED OUT\n"; exit 1; fi; \
	  done; \
	done
	@echo "All nodes ready."

.PHONY: versions
versions: ## Print what each node actually installed (the reproducibility ground truth)
	@for ip in $$(terraform output -json ssh | python3 -c 'import json,sys; [print(v.split("@")[1]) for v in json.load(sys.stdin).values()]'); do \
	  echo "--- $$ip ---"; \
	  ssh -i $(KEY) -o StrictHostKeyChecking=accept-new -o BatchMode=yes ubuntu@$$ip \
	    'cat /etc/olaitan-bootstrap.json; echo; echo "running kernel: $$(uname -r)"'; \
	done

.PHONY: cp
cp: ## SSH to the control plane
	@ssh -i $(KEY) -o StrictHostKeyChecking=accept-new \
	  ubuntu@$$(terraform output -json control_plane | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_ip"])')

.PHONY: kubeconfig
kubeconfig: ## Fetch admin.conf from the control plane and rewrite it to the public IP
	@ip=$$(terraform output -json control_plane | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_ip"])'); \
	ssh -i $(KEY) -o StrictHostKeyChecking=accept-new -o BatchMode=yes ubuntu@$$ip \
	  'sudo cat /etc/kubernetes/admin.conf' > kubeconfig.olaitan; \
	sed -i "s#server: https://.*:6443#server: https://$$ip:6443#" kubeconfig.olaitan; \
	chmod 600 kubeconfig.olaitan; \
	echo "wrote kubeconfig.olaitan (gitignored); export KUBECONFIG=$$PWD/kubeconfig.olaitan"

.PHONY: stop
stop: ## Stop the nodes. Keeps the disks, releases the public IPs, stops the per-hour compute charge.
	@ids=$$(terraform output -json instance_ids | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'); \
	$(AWS) ec2 stop-instances --instance-ids $$ids --query 'StoppingInstances[].{Id:InstanceId,State:CurrentState.Name}' --output table

.PHONY: start
start: ## Start the nodes again. Public IPs will be NEW; re-run make kubeconfig.
	@ids=$$(terraform output -json instance_ids | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'); \
	$(AWS) ec2 start-instances --instance-ids $$ids --query 'StartingInstances[].{Id:InstanceId,State:CurrentState.Name}' --output table
	@echo "Note: kubeadm certificates embed the PRIVATE IP, which is preserved across stop/start, so the cluster survives. The PUBLIC IP changes."

.PHONY: status
status: ## Show node state and current cost rate
	@$(AWS) ec2 describe-instances \
	  --filters 'Name=tag:Project,Values=olaitan' 'Name=instance-state-name,Values=pending,running,stopping,stopped' \
	  --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,Type:InstanceType,State:State.Name,PublicIp:PublicIpAddress}' \
	  --output table

.PHONY: down
down: ## Destroy everything. Check your runs/ artefacts are pulled first.
	@echo "This destroys the cluster and its disks. Artefacts in runs/ on the nodes will be LOST."
	@terraform destroy
