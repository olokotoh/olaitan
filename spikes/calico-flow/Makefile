SHELL := /usr/bin/env bash
CLUSTER_NAME ?= olaitan-flow-spike
KIND_NODE_IMAGE ?= kindest/node:v1.30.0
CALICO_VERSION ?= v3.31.5
TLS_DIR ?= /tmp/goldmane-tls

.PHONY: spike cluster goldmane traffic capture bench test cleanup tls

spike: cluster goldmane traffic tls capture bench
	@echo "spike: full bring-up + capture + bench complete"

cluster:
	kind create cluster --name $(CLUSTER_NAME) --image $(KIND_NODE_IMAGE) --config kind-config.yaml

goldmane:
	kubectl --context kind-$(CLUSTER_NAME) create -f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/tigera-operator.yaml
	kubectl --context kind-$(CLUSTER_NAME) rollout status -n tigera-operator deployment/tigera-operator --timeout=180s
	kubectl --context kind-$(CLUSTER_NAME) create -f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/custom-resources.yaml
	@echo "waiting for goldmane to be ready (timeout 5m)..."
	@i=0; until kubectl --context kind-$(CLUSTER_NAME) -n calico-system get deployment goldmane -o jsonpath='{.status.readyReplicas}' 2>/dev/null | grep -q 1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then echo "FAIL: goldmane not ready after 5 minutes" >&2; exit 1; fi; sleep 5; \
	done
	@echo "goldmane ready"

traffic:
	kubectl --context kind-$(CLUSTER_NAME) apply -f traffic.yaml
	@echo "waiting for traffic pods (timeout 3m)..."
	@i=0; until [ "$$(kubectl --context kind-$(CLUSTER_NAME) -n spike-traffic get pod target -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && [ "$$(kubectl --context kind-$(CLUSTER_NAME) -n spike-traffic get pod client -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; do \
		i=$$((i+1)); if [ $$i -ge 36 ]; then echo "FAIL: traffic pods not ready after 3 minutes" >&2; exit 1; fi; sleep 5; \
	done
	@echo "traffic pods ready; waiting 45s for first Felix flush + Goldmane window..."
	@sleep 45

tls:
	mkdir -p $(TLS_DIR)
	kubectl --context kind-$(CLUSTER_NAME) -n calico-system get configmap tigera-ca-bundle -o jsonpath='{.data.tigera-ca-bundle\.crt}' > $(TLS_DIR)/ca.crt
	kubectl --context kind-$(CLUSTER_NAME) -n calico-system get secret whisker-backend-key-pair -o jsonpath='{.data.tls\.crt}' | base64 -d > $(TLS_DIR)/client.crt
	kubectl --context kind-$(CLUSTER_NAME) -n calico-system get secret whisker-backend-key-pair -o jsonpath='{.data.tls\.key}' | base64 -d > $(TLS_DIR)/client.key
	@echo "tigera CA + client cert in $(TLS_DIR)/"

capture: tls
	@echo "starting goldmane port-forward..."
	@kubectl --context kind-$(CLUSTER_NAME) -n calico-system port-forward svc/goldmane 7443:7443 > /tmp/pf-goldmane.log 2>&1 & echo $$! > /tmp/pf-goldmane.pid
	@sleep 4
	go run . --mode capture --addr localhost:7443 --ca $(TLS_DIR)/ca.crt --cert $(TLS_DIR)/client.crt --key $(TLS_DIR)/client.key --src-ns spike-traffic --dst-ns spike-traffic --timeout 60
	@kill $$(cat /tmp/pf-goldmane.pid) 2>/dev/null || true

bench: tls
	@echo "starting goldmane port-forward..."
	@kubectl --context kind-$(CLUSTER_NAME) -n calico-system port-forward svc/goldmane 7443:7443 > /tmp/pf-goldmane.log 2>&1 & echo $$! > /tmp/pf-goldmane.pid
	@sleep 4
	go run . --mode bench --addr localhost:7443 --ca $(TLS_DIR)/ca.crt --cert $(TLS_DIR)/client.crt --key $(TLS_DIR)/client.key --timeout 600
	@kill $$(cat /tmp/pf-goldmane.pid) 2>/dev/null || true

test:
	go test -race ./...

cleanup:
	./cleanup.sh
	rm -rf $(TLS_DIR)
