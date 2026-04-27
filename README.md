# Olaitan

**LLM-powered autonomous runtime security agent for Kubernetes.**

Olaitan correlates telemetry from five concurrent signal layers — eBPF syscall traces, Kubernetes API audit logs, container runtime events, network flow data, and application logs — through a three-tier detection engine (Sigma rules, statistical baselines, LLM analyst) and autonomously contains threats via a graduated isolation state machine.

> *Olaitan* (Yoruba): "Wealth does not finish" — the wealth of security intelligence that never runs out.

## Status

Under active development as a final year project (Cybersecurity, Miva Open University).

## Architecture

- **Language:** Go
- **Deployment:** Kubernetes-native (DaemonSet collectors + Deployment aggregator)
- **Infrastructure:** kubeadm (3 nodes), Calico CNI, Falco, NATS, Redis
- **LLM:** Provider-agnostic (Claude, OpenAI, Ollama, or any OpenAI-compatible API)

## Quick Start

```bash
# Deploy full stack + run attack scenarios
make demo

# Run comparative evaluation (Falco-only vs rules+stats vs LLM-augmented)
make demo-compare
```

## Deploy

Olaitan ships as a Helm chart under `deploy/helm/olaitan/` with Falco,
NATS JetStream, and Redis declared as conditional subchart dependencies.

- **[deploy/helm/README.md](deploy/helm/README.md)** — Operator guide: prerequisites, install, values, uninstall.
- **[deploy/demo/setup.sh](deploy/demo/setup.sh)** — Cluster bootstrap helper (kubeadm + Calico preflight, Helm repo + dependency-update commands).

```bash
# One-shot bootstrap (print preflight + add helm repos + fetch subcharts):
./deploy/demo/setup.sh --apply

# Install:
make helm-prepare
helm install olaitan ./deploy/helm/olaitan
```

## Project Structure

```
cmd/                    # Binary entrypoints
internal/               # Core packages (schema, collector, correlator, decision, response, report)
config/                 # Default olaitan.yaml + prompt templates
rules/                  # Sigma-style YAML detection rules
deploy/
  helm/olaitan/         # Helm chart
  demo/                 # Attack scenarios + demo scripts
```

## License

MIT
