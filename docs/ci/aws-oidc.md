# AWS OIDC for real integration tests

This repository runs AWS Secrets Manager conformance tests against a real account on scheduled/manual workflows using GitHub OIDC.

## IAM role trust policy

Trust policy must allow GitHub OIDC with repo scoping, e.g.:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:greenticai/greentic-secrets:*"
        }
      }
    }
  ]
}
```

## Minimal permissions

- `secretsmanager:CreateSecret`
- `secretsmanager:PutSecretValue`
- `secretsmanager:GetSecretValue`
- `secretsmanager:DeleteSecret`
- `secretsmanager:ListSecrets` (optional, used for cleanup)
- `kms:Encrypt` / `kms:Decrypt` on the chosen key

Scope permissions to a prefix (e.g. `ci/aws/*`) or by tag on created secrets/keys.

## GitHub variables

- `AWS_OIDC_ROLE_ARN`: role to assume
- `AWS_REGION`: region to run tests in
- `GREENTIC_AWS_KMS_KEY_ID`: (optional) pre-provisioned KMS key for real runs; otherwise provide permissions to create one.


