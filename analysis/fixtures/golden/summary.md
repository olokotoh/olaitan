# Olaitan analysis summary

## Run-set provenance

- runs_dir: `analysis/fixtures/runs`
- fixture: True
- total_runs: 124
- distinct_manifest_count: 1
- prereg: `analysis/preregistration.md`

> NOTE: this is a SYNTHETIC fixture run-set (`fixture: true`). The numbers below are for the data-path proof + the smoke test only and are NEVER thesis-final (BI-7). The real 400-run numbers land later on the cluster (Story 5.9).

## Per-cell metrics

| config | scenario | metric_or_test | value | n | test | test_id | alpha_corrected | p_value | status | manifest_hash | mixed_manifest | fsm_source_partition | underpowered |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| f | s1 | detection_rate | 0.250000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s1 | mttd_median | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s1 | mttd_mean | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s1 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | False |
| f | s2 | detection_rate | 0.250000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s2 | mttd_median | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s2 | mttd_mean | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s2 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | False |
| f | s3 | detection_rate | 0.250000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s3 | mttd_median | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s3 | mttd_mean | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s3 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | False |
| f | s4 | detection_rate | 0.250000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s4 | mttd_median | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s4 | mttd_mean | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s4 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | False |
| f | s5 | detection_rate | 0.250000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s5 | mttd_median | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s5 | mttd_mean | 40.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | True |
| f | s5 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=1;detection_signal_only=0;none=3 | False |
| rs | s1 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s1 | mttd_median | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s1 | mttd_mean | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s1 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rs | s2 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s2 | mttd_median | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s2 | mttd_mean | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s2 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rs | s3 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s3 | mttd_median | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s3 | mttd_mean | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s3 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rs | s4 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s4 | mttd_median | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s4 | mttd_mean | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s4 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rs | s5 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s5 | mttd_median | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s5 | mttd_mean | 30.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rs | s5 | attack_kappa | n/a | 0 | descriptive |  | n/a | n/a | n/a | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rsl | s1 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s1 | mttd_median | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s1 | mttd_mean | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s1 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rsl | s2 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s2 | mttd_median | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s2 | mttd_mean | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s2 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rsl | s3 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s3 | mttd_median | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s3 | mttd_mean | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s3 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rsl | s4 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s4 | mttd_median | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s4 | mttd_mean | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s4 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rsl | s5 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s5 | mttd_median | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s5 | mttd_mean | 22.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rsl | s5 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rslt-full | s1 | detection_rate | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s1 | mttd_median | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s1 | mttd_mean | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s1 | attack_kappa | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | False |
| rslt-full | s2 | detection_rate | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s2 | mttd_median | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s2 | mttd_mean | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s2 | attack_kappa | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | False |
| rslt-full | s3 | detection_rate | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s3 | mttd_median | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s3 | mttd_mean | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s3 | attack_kappa | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | False |
| rslt-full | s4 | detection_rate | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s4 | mttd_median | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s4 | mttd_mean | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s4 | attack_kappa | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | False |
| rslt-full | s5 | detection_rate | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s5 | mttd_median | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s5 | mttd_mean | 18.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | True |
| rslt-full | s5 | attack_kappa | 1.000000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=4;detection_signal_only=0;none=0 | False |
| rslt-l1-only | s1 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s1 | mttd_median | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s1 | mttd_mean | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s1 | attack_kappa | 1.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rslt-l1-only | s2 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s2 | mttd_median | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s2 | mttd_mean | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s2 | attack_kappa | 1.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rslt-l1-only | s3 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s3 | mttd_median | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s3 | mttd_mean | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s3 | attack_kappa | 1.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rslt-l1-only | s4 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s4 | mttd_median | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s4 | mttd_mean | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s4 | attack_kappa | 1.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rslt-l1-only | s5 | detection_rate | 0.500000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s5 | mttd_median | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s5 | mttd_mean | 28.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | True |
| rslt-l1-only | s5 | attack_kappa | 1.000000 | 2 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=2;detection_signal_only=0;none=2 | False |
| rslt-l1-l2 | s1 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s1 | mttd_median | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s1 | mttd_mean | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s1 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rslt-l1-l2 | s2 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s2 | mttd_median | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s2 | mttd_mean | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s2 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rslt-l1-l2 | s3 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s3 | mttd_median | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s3 | mttd_mean | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s3 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rslt-l1-l2 | s4 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s4 | mttd_median | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s4 | mttd_mean | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s4 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| rslt-l1-l2 | s5 | detection_rate | 0.750000 | 4 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s5 | mttd_median | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s5 | mttd_mean | 24.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | True |
| rslt-l1-l2 | s5 | attack_kappa | 1.000000 | 3 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False | observed=3;detection_signal_only=0;none=1 | False |
| f | benign | fpr_per_hour | 0.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False |  | False |
| rs | benign | fpr_per_hour | 0.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False |  | False |
| rsl | benign | fpr_per_hour | 1.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False |  | False |
| rslt-full | benign | fpr_per_hour | 1.000000 | 1 | descriptive |  | n/a | n/a | run | fixture0000000000000000000000000000000000000000000000000000000000 | False |  | False |

## Confirmatory results

| config | scenario | metric_or_test | value | n | test | test_id | alpha_corrected | p_value | status | manifest_hash | mixed_manifest | fsm_source_partition | underpowered |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rsl | benign-sweep | rsl vs 2.0/hour bound | 1.000000 | 1 | poisson_one_sided | RQ3-FPR-POISSON | 0.025000 | 0.406006 | run | n/a | False |  | False |
| rslt-full | benign-sweep | rslt-full vs 2.0/hour bound | 1.000000 | 1 | poisson_one_sided | RQ3-FPR-POISSON | 0.025000 | 0.406006 | run | n/a | False |  | False |
| rslt-full | s1 | rslt-full vs f | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.250000 | run | n/a | False |  | False |
| rslt-full | s2 | rslt-full vs f | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.250000 | run | n/a | False |  | False |
| rslt-full | s3 | rslt-full vs f | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.250000 | run | n/a | False |  | False |
| rslt-full | s4 | rslt-full vs f | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.250000 | run | n/a | False |  | False |
| rslt-full | s5 | rslt-full vs f | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.250000 | run | n/a | False |  | False |
| rslt-full | s1 | rslt-full vs rs | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.500000 | run | n/a | False |  | False |
| rslt-full | s2 | rslt-full vs rs | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.500000 | run | n/a | False |  | False |
| rslt-full | s3 | rslt-full vs rs | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.500000 | run | n/a | False |  | False |
| rslt-full | s4 | rslt-full vs rs | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.500000 | run | n/a | False |  | False |
| rslt-full | s5 | rslt-full vs rs | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 0.500000 | run | n/a | False |  | False |
| rslt-full | s1 | rslt-full vs rsl | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 1.000000 | run | n/a | False |  | False |
| rslt-full | s2 | rslt-full vs rsl | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 1.000000 | run | n/a | False |  | False |
| rslt-full | s3 | rslt-full vs rsl | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 1.000000 | run | n/a | False |  | False |
| rslt-full | s4 | rslt-full vs rsl | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 1.000000 | run | n/a | False |  | False |
| rslt-full | s5 | rslt-full vs rsl | 0.000000 | 4 | mcnemar | RQ1-DR-MCNEMAR | 0.010000 | 1.000000 | run | n/a | False |  | False |
| all | s1 | MTTD across configs | 9.000000 | 10 | kruskal_wallis+dunn(holm) | RQ2-MTTD-KW-DUNN-HOLM | n/a | 0.029291 | run | n/a | False |  | False |
| all | s2 | MTTD across configs | 9.000000 | 10 | kruskal_wallis+dunn(holm) | RQ2-MTTD-KW-DUNN-HOLM | n/a | 0.029291 | run | n/a | False |  | False |
| all | s3 | MTTD across configs | 9.000000 | 10 | kruskal_wallis+dunn(holm) | RQ2-MTTD-KW-DUNN-HOLM | n/a | 0.029291 | run | n/a | False |  | False |
| all | s4 | MTTD across configs | 9.000000 | 10 | kruskal_wallis+dunn(holm) | RQ2-MTTD-KW-DUNN-HOLM | n/a | 0.029291 | run | n/a | False |  | False |
| all | s5 | MTTD across configs | 9.000000 | 10 | kruskal_wallis+dunn(holm) | RQ2-MTTD-KW-DUNN-HOLM | n/a | 0.029291 | run | n/a | False |  | False |
| rubric | clarity | LLM vs templated | n/a | 0 | wilcoxon | RQ5-RUBRIC-WILCOXON-CLARITY | 0.010000 | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rubric | completeness | LLM vs templated | n/a | 0 | wilcoxon | RQ5-RUBRIC-WILCOXON-COMPLETENESS | 0.010000 | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rubric | attack-coverage | LLM vs templated | n/a | 0 | wilcoxon | RQ5-RUBRIC-WILCOXON-ATTACK-COVERAGE | 0.010000 | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rubric | killchain | LLM vs templated | n/a | 0 | wilcoxon | RQ5-RUBRIC-WILCOXON-KILLCHAIN | 0.010000 | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rubric | actionability | LLM vs templated | n/a | 0 | wilcoxon | RQ5-RUBRIC-WILCOXON-ACTIONABILITY | 0.010000 | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rubric | rater-agreement | inter-rater | n/a | 0 | icc2k | RQ5-ICC | n/a | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |
| rsl;rslt-full | benign-adversarial | fr55_trust_bound | n/a | 0 | empirical_bound_count | RQ4-FR55-BOUND | n/a | n/a | skipped (insufficient data, n=0) | n/a | False |  | False |

## RSLT ablation

| config | scenario | metric_or_test | value | n | test | test_id | alpha_corrected | p_value | status | manifest_hash | mixed_manifest | fsm_source_partition | underpowered |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| l2_contribution | s1 | l2_contribution (technique T1611) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-L2-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-l1-l2 | s1 | L1+L2 vs L1-only | 0.000000 | 4 | mcnemar | RQ4-ABL-L2-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| senior_contribution | s1 | senior_contribution (technique T1611) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-SENIOR-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-full | s1 | full vs L1+L2 | 0.000000 | 4 | mcnemar | RQ4-ABL-SENIOR-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| l2_contribution | s2 | l2_contribution (technique T1552) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-L2-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-l1-l2 | s2 | L1+L2 vs L1-only | 0.000000 | 4 | mcnemar | RQ4-ABL-L2-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| senior_contribution | s2 | senior_contribution (technique T1552) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-SENIOR-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-full | s2 | full vs L1+L2 | 0.000000 | 4 | mcnemar | RQ4-ABL-SENIOR-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| l2_contribution | s3 | l2_contribution (technique T1613) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-L2-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-l1-l2 | s3 | L1+L2 vs L1-only | 0.000000 | 4 | mcnemar | RQ4-ABL-L2-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| senior_contribution | s3 | senior_contribution (technique T1613) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-SENIOR-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-full | s3 | full vs L1+L2 | 0.000000 | 4 | mcnemar | RQ4-ABL-SENIOR-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| l2_contribution | s4 | l2_contribution (technique T1071) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-L2-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-l1-l2 | s4 | L1+L2 vs L1-only | 0.000000 | 4 | mcnemar | RQ4-ABL-L2-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| senior_contribution | s4 | senior_contribution (technique T1071) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-SENIOR-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-full | s4 | full vs L1+L2 | 0.000000 | 4 | mcnemar | RQ4-ABL-SENIOR-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| l2_contribution | s5 | l2_contribution (technique T1496) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-L2-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-l1-l2 | s5 | L1+L2 vs L1-only | 0.000000 | 4 | mcnemar | RQ4-ABL-L2-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |
| senior_contribution | s5 | senior_contribution (technique T1496) | 0.250000 | 4 | dr_difference;ci95=[0.000000, 0.750000] | RQ4-ABL-SENIOR-MCNEMAR | n/a | n/a | run | n/a | False |  | False |
| rslt-full | s5 | full vs L1+L2 | 0.000000 | 4 | mcnemar | RQ4-ABL-SENIOR-MCNEMAR | 0.005000 | 1.000000 | run | n/a | False |  | False |

## Exploratory analyses

No exploratory tests emitted (every test_id is in the confirmatory registry).

