# AWS IAM Connector

The `aws_iam` connector discovers IAM identities, credentials, and policies from
an AWS account and maps them onto Sentinel's governance model. It is read-only:
it never creates, mutates, or deletes anything in AWS.

| Property | Value |
| --- | --- |
| Connector key | `aws_iam` |
| Source system | `aws_iam` |
| Backing SDK | AWS SDK for Go v2 (`iam`, `sts`) |
| Runtime credentials | Default credential chain (or configured static keys) |
| Writes to AWS | None |

## What it discovers

| AWS resource | Sentinel model |
| --- | --- |
| IAM Users | `Identity` (`human`) |
| IAM Roles | `Identity` (`workload`) |
| IAM Groups | `Identity` (`team`) |
| Access keys (active/inactive) | `Credential` (`access_key`) |
| Attached managed policies (ARNs) | `Resource` (`iam_policy`) + `AccessGrant` |
| Inline policies (user/role/group) | `Resource` (`iam_policy`) + `AccessGrant` |

Identity attributes captured include `account_id`, IAM resource IDs, path,
AWS-managed tags (`tag:key`), and MFA status (`mfa_enabled`). For users the
connector records `password_enrolled` and `last_used`.

## Risk heuristics

Risk scores (0-100) are an initial heuristic, overridden by policy evaluation
and analyst review:

- Users without MFA: base +35
- Loose managed policies (`AdministratorAccess`, `*`-broad policy): +30
- Access keys not rotated in 90+ days: +25 (`stale_*_days` attribute added)
- Workload roles: base 35 (assumed higher standing privileges)
- Groups: base 15

## Configuration

### Options

| Option | Description | Default |
| --- | --- | --- |
| `region` | AWS region to target | `AWS_REGION` / `AWS_DEFAULT_REGION` / `us-east-1` |
| `role_arn` | ARN to assume (sets `stscreds` provider) | none |
| `external_id` | External ID for the assumed role | none |
| `environment` | Environment tag applied to discovered objects | `unknown` |

### Secrets

| Secret | Description |
| --- | --- |
| `access_key_id` | Static access key (only if not using the chain) |
| `secret_access_key` | Static secret key |

When neither secret is set, the standard AWS credential chain is used (env
variables, shared config, EC2 instance role, ECS, etc.). Secrets are encrypted
at rest by Sentinel and never returned through the API.

## Least-privilege IAM policy for the collector

Attach the following inline policy to the principal Sentinel uses to run the
connector. It grants only the read calls the connector performs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelIamDiscovery",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SentinelGetAccountId",
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

If the collector runs via `role_arn`, set `AccountId`/`ExternalId` conditions
and restrict the `iam:List*` resource to `"arn:aws:iam::*:root"`-style scoping
as required by your perimeter controls.

## Example

Create the connector config through the API:

```sh
curl -sS -X POST http://localhost:8080/v1/connectors \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "key": "aws_iam",
    "name": "prod-aws",
    "enabled": true,
    "interval_minutes": 60,
    "options": { "region": "eu-west-1", "environment": "production" },
    "secrets": { "access_key_id": "...", "secret_access_key": "..." }
  }'
```

Then run it on demand: `POST /v1/connectors/{id}/run` or let the scheduler run
it every 60 minutes.

## Troubleshooting

- `failed to load config: ...` — the credential chain could not resolve
  credentials; configure static secrets or use the AWS environment.
- `action access denied` — the collector policy is missing one of the
  `iam:List*` actions listed above.
- Region mismatch — IAM is global, but calls are bound to the configured
  region; any region works for IAM.