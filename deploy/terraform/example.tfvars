# Copy to terraform.tfvars and edit. terraform.tfvars is gitignored.

# The only address allowed to reach SSH and the Kubernetes API.
# Find yours with: curl -s https://checkip.amazonaws.com
# This changes whenever your ISP reassigns you; re-apply when it does.
workstation_cidr = "203.0.113.10/32"

# An existing EC2 key pair IN THIS ACCOUNT AND REGION. Required: there is no
# default, because a default can only ever be right for one account, and a
# wrong one fails at apply time with an error that does not say what to fix.
# List yours with: aws ec2 describe-key-pairs --query "KeyPairs[].KeyName"
key_name = "olaitan-e2e"

# The AWS CLI profile to authenticate with, if not "default".
# profile = "my-profile"

# Only needed if your private key is not at ~/.ssh/<key_name>.pem. It is
# read by nothing; it only makes the `ssh` output copy-pasteable.
# ssh_private_key_path = "~/.ssh/some-other-name.pem"

# Defaults below are the spec from hack/bootstrap-kubeadm.md. Override
# only with a reason you are willing to write into the thesis.
# node_instance_type = "c5.xlarge"
# worker_count       = 2
# root_volume_gb     = 50
