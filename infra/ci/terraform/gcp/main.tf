provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  repo_slug = "${var.github_owner}/${var.github_repo}"
}

resource "google_iam_workload_identity_pool" "pool" {
  workload_identity_pool_id = var.pool_id
  display_name              = "GitHub Actions Pool"
  description               = "WIF pool for greentic-secrets CI"
}

resource "google_iam_workload_identity_pool_provider" "provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "GitHub Provider"
  description                        = "GitHub OIDC provider for CI"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  attribute_condition = "assertion.repository == \"${local.repo_slug}\" && assertion.ref == \"${var.github_ref_pattern}\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "ci" {
  account_id   = var.service_account_id
  display_name = "Greentic Secrets CI"
}

resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.pool.name}/attribute.repository/${local.repo_slug}"
  ]
}

resource "google_project_iam_custom_role" "secret_role" {
  role_id     = "GreenticSecretsCi"
  title       = "Greentic Secrets CI"
  description = "Minimal Secret Manager permissions for CI"
  permissions = [
    "secretmanager.secrets.create",
    "secretmanager.secrets.delete",
    "secretmanager.secrets.get",
    "secretmanager.secrets.update",
    "secretmanager.versions.add",
    "secretmanager.versions.access",
  ]
}

resource "google_project_iam_binding" "secret_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.secret_role.name
  members = ["serviceAccount:${google_service_account.ci.email}"]
}

