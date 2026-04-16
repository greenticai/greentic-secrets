provider "azuread" {
  tenant_id = var.tenant_id
}

data "azuread_client_config" "current" {}

locals {
  repo_slug = "${var.github_owner}/${var.github_repo}"
  subject   = var.github_environment != "" ? "repo:${local.repo_slug}:environment:${var.github_environment}" : "repo:${local.repo_slug}:ref:refs/heads/main"
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azuread_application" "app" {
  display_name = "greentic-secrets-ci-${var.github_repo}"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "sp" {
  client_id = azuread_application.app.client_id
}

resource "azuread_application_federated_identity_credential" "github" {
  application_object_id = azuread_application.app.object_id
  display_name          = "github-${var.github_repo}"
  audiences             = ["api://AzureADTokenExchange"]
  issuer                = "https://token.actions.githubusercontent.com"
  subject               = local.subject
}

resource "azurerm_key_vault" "kv" {
  name                       = var.key_vault_name
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = var.use_rbac
  tags                       = var.tags
}

resource "azurerm_role_assignment" "kv_role" {
  count                = var.use_rbac ? 1 : 0
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azuread_service_principal.sp.object_id
}

resource "azurerm_key_vault_access_policy" "kv_policy" {
  count        = var.use_rbac ? 0 : 1
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = var.tenant_id
  object_id    = azuread_service_principal.sp.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Recover"]
}

