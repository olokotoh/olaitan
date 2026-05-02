// Independent module for the CRIU forensic checkpoint feasibility spike
// (Story 1.4). Deliberately stdlib-only so its dependency closure cannot
// bleed into the main olaitan module's go.sum.
module github.com/olokotoh/olaitan/spikes/criu-checkpoint

go 1.22
