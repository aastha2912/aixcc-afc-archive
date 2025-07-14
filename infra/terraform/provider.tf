provider "azurerm" {
  features {
  }
  environment                     = "public"
  use_msi                         = false
  use_cli                         = true
  use_oidc                        = false
  resource_provider_registrations = "none"
  subscription_id                 = var.subscription-id
}

provider "azapi" {
}
