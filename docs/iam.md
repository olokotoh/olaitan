# IAM and S3 bucket least-privilege (report archive, Story 4.6, FR45/AC3/AC4)

This document records the least-privilege IAM split and the S3 bucket
preconditions for the durable report writer (`internal/report/archive/`, Story
4.6). The architecture's authentication section is the source of record
(object-write-only on the report bucket; read-only credentials issued
separately). The writer CODE uses ONLY the three operations granted below; the
split itself is enforced by the operator's IAM policy, NOT by the writer code.

## Bucket preconditions (operator/Helm; the writer NEVER creates the bucket)

The report bucket MUST be provisioned by the operator BEFORE
`response.report_archive.enabled=true`. The writer never calls `MakeBucket` in
production (a writer must never assume create-bucket rights).

- **Object lock ENABLED.** Create the bucket with object lock enabled. This is
  set ONLY at bucket creation and cannot be retro-enabled. Enabling object lock
  forces **versioning** on.
- **Versioning ENABLED.** Required by object lock (set automatically when object
  lock is enabled at creation).
- **SSE-KMS default encryption.** Set the bucket default encryption to SSE-KMS
  with the same key alias configured in `response.report_archive.kms_key_alias`.
  The writer applies an explicit SSE-KMS PUT directive per object; the bucket
  default is the belt-and-braces fallback.
- **Access logging ENABLED (AC3).** Enable S3 server access logging (or MinIO
  bucket audit) on the report bucket so every `PutObject` / `HeadObject` is
  captured in an auditable trail. The writer adds no operation the access log
  would miss (it is write-and-head only).

AWS CLI example (bucket creation with object lock):

```
aws s3api create-bucket --bucket olaitan-reports \
  --object-lock-enabled-for-bucket \
  --region eu-west-1 --create-bucket-configuration LocationConstraint=eu-west-1
aws s3api put-bucket-versioning --bucket olaitan-reports \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket olaitan-reports \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/olaitan-reports"}}}]'
aws s3api put-bucket-logging --bucket olaitan-reports \
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"olaitan-access-logs","TargetPrefix":"olaitan-reports/"}}'
```

MinIO example: create the bucket with object lock via
`mc mb --with-lock myminio/olaitan-reports`, then `mc encrypt set sse-kms
alias/olaitan-reports myminio/olaitan-reports`.

## Least-privilege IAM split (AC4)

Two SEPARATE identities. The writer identity is write-and-head only; reads go to
a distinct `olaitan-reporter` identity.

### Writer identity (the Olaitan aggregator)

Grants ONLY `s3:PutObject`, `s3:PutObjectLegalHold`, and `s3:HeadObject` on the
report bucket. The writer CODE uses `PutObject` (the report PUT, with the
object-lock retain-until directive carried as PUT headers) and `HeadObject` (the
dedup HEAD); `s3:PutObjectLegalHold` is granted for the object-lock posture and
any future legal-hold use. The writer NEVER calls `DeleteObject`, `ListObjects`,
or `GetObject` -- do NOT add a fourth action.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OlaitanReportWriter",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectLegalHold",
        "s3:HeadObject"
      ],
      "Resource": "arn:aws:s3:::olaitan-reports/reports/*"
    },
    {
      "Sid": "OlaitanReportWriterKMS",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Encrypt"],
      "Resource": "arn:aws:kms:*:*:alias/olaitan-reports"
    }
  ]
}
```

The S3 access/secret keys for this identity are the NFR8 secret-via-env pattern:
`S3_ACCESS_KEY` / `S3_SECRET_KEY` (Helm `secrets.s3AccessKey` /
`secrets.s3SecretKey`), never a file in the image or a ConfigMap.

### Reader identity (`olaitan-reporter`, separate)

A distinct identity for any consumer that reads archived reports (a SIEM, an
analyst, a compliance auditor). It is read-only and is NEVER the writer's
credentials.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OlaitanReporterRead",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetObjectRetention"],
      "Resource": [
        "arn:aws:s3:::olaitan-reports",
        "arn:aws:s3:::olaitan-reports/reports/*"
      ]
    },
    {
      "Sid": "OlaitanReporterKMSDecrypt",
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "arn:aws:kms:*:*:alias/olaitan-reports"
    }
  ]
}
```

### Object-lock override (privileged, audited)

With `object_lock_mode: GOVERNANCE` (the default), a mis-written report can be
corrected ONLY by a privileged identity holding `s3:BypassGovernanceRetention`
(plus `s3:DeleteObjectVersion`). This is a break-glass identity, NOT the writer
and NOT `olaitan-reporter`; granting it is an operator decision and every use is
audited (the access-logging precondition above). With `object_lock_mode:
COMPLIANCE` there is NO override: objects are immutable until the retain-until
date expires.
