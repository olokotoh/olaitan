# Copy to terraform.tfvars and edit. terraform.tfvars is gitignored.

# The only address allowed to reach SSH and the Kubernetes API.
# Find yours with: curl -s https://checkip.amazonaws.com
# This changes whenever your ISP reassigns you; re-apply when it does.
workstation_cidr = "203.0.113.10/32"

# Defaults below are the spec from hack/bootstrap-kubeadm.md. Override
# only with a reason you are willing to write into the thesis.
# node_instance_type = "c5.xlarge"
# worker_count       = 2
# root_volume_gb     = 50
