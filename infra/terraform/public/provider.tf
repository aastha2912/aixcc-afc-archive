provider "azurerm" {
  features {
  }
  environment                     = "public"
  use_msi                         = false
  use_cli                         = true
  use_oidc                        = false
  resource_provider_registrations = "none"
  subscription_id                 = "cb3c835a-f42b-4828-bfec-d8c51d86f256"
}
