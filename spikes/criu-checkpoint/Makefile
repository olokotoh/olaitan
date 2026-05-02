## CRIU forensic checkpoint feasibility spike — Story 1.4.
##
## Targets:
##   spike     — full reproduction: cluster up, install CRIU, deploy workload,
##               attempt checkpoint, capture artefacts, run privacy scan,
##               and tear down. ~5 minutes on first run, ~3 minutes thereafter.
##   cluster   — bring up only the kind cluster (no workload, no checkpoint).
##   workload  — deploy the busybox sleep test workload.
##   checkpoint— trigger the kubelet checkpoint API call (cluster + workload required).
##   harness   — run the Go harness (cluster + workload required).
##   verify    — run go vet + go test on the spike module (no cluster needed).
##   clean     — tear down the kind cluster.
##
## Environment variables:
##   CLUSTER_NAME (default: olaitan-criu-spike)

CLUSTER_NAME ?= olaitan-criu-spike
WORKLOAD_NS  ?= criu-spike
WORKLOAD_POD ?= busybox-target
WORKLOAD_CON ?= busybox

.PHONY: spike cluster workload checkpoint harness verify clean

spike: cluster workload harness

cluster:
	@echo "==> Bringing up kind cluster: $(CLUSTER_NAME)"
	kind create cluster --config kind-config.yaml --wait 2m
	@echo "==> Installing CRIU inside the kind node"
	docker exec $(CLUSTER_NAME)-control-plane apt-get update -qq
	docker exec $(CLUSTER_NAME)-control-plane apt-get install -y -qq criu
	@echo "==> Verifying CRIU kernel feature support"
	-docker exec $(CLUSTER_NAME)-control-plane criu check --all || true
	@echo "==> Verifying ContainerCheckpoint feature gate"
	kubectl get --raw /api/v1/nodes/$(CLUSTER_NAME)-control-plane/proxy/configz \
		| python3 -c 'import json,sys; print(json.load(sys.stdin)["kubeletconfig"].get("featureGates",{}))'

workload:
	@echo "==> Deploying test workload"
	kubectl apply -f workload.yaml
	kubectl -n $(WORKLOAD_NS) wait --for=condition=Ready pod/$(WORKLOAD_POD) --timeout=60s

harness:
	@echo "==> Running Go harness (3 checkpoint attempts, AC5 timing)"
	go run . \
		-namespace=$(WORKLOAD_NS) \
		-pod=$(WORKLOAD_POD) \
		-container=$(WORKLOAD_CON) \
		-runs=3

checkpoint:
	@echo "==> Direct kubelet checkpoint API call (curl)"
	@NODE=$$(kubectl get node $(CLUSTER_NAME)-control-plane -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'); \
	echo "Node IP: $$NODE"; \
	kubectl proxy --port=8001 & PROXY_PID=$$!; \
	sleep 2; \
	time curl -sk -X POST \
		"http://localhost:8001/api/v1/nodes/$(CLUSTER_NAME)-control-plane/proxy/checkpoint/$(WORKLOAD_NS)/$(WORKLOAD_POD)/$(WORKLOAD_CON)" \
		-w "\nHTTP %{http_code}\n" || true; \
	kill $$PROXY_PID 2>/dev/null || true

verify:
	go vet ./...
	go test -race ./...

clean:
	@bash ./cleanup.sh
