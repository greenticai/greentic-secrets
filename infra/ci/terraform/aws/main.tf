provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  repo_slug = "${var.github_owner}/${var.github_repo}"
  prefix    = "${var.secrets_prefix}/${local.repo_slug}"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = var.client_id_list
  thumbprint_list = var.thumbprint_list
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo_slug}:ref:${var.github_ref_pattern}"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = var.tags
}

data "template_file" "policy" {
  template = file("${path.module}/iam_policy.json.tftpl")
  vars = {
    region     = var.aws_region
    account_id = data.aws_caller_identity.current.account_id
    prefix     = local.prefix
  }
}

resource "aws_iam_policy" "secrets" {
  name   = "${var.role_name}-secrets"
  policy = data.template_file.policy.rendered
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.secrets.arn
}
