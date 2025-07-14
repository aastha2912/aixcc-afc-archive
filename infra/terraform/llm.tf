resource "random_id" "ai-subdomain" {
  byte_length = 8
}

output "crs_ai_subdomain" {
  value = random_id.ai-subdomain.hex
}

resource "azurerm_ai_services" "main" {
  custom_subdomain_name = random_id.ai-subdomain.hex
  location              = "eastus2"
  name                  = random_id.ai-subdomain.hex
  resource_group_name   = azurerm_resource_group.main.name
  sku_name              = "S0"
}

# azurerm_ai_services.main.endpoint
# azurerm_ai_services.main.primary_access_key

/*
gpt-4.1-2025-04-14
gpt-4o-mini-2024-07-18
gpt-4o-2024-08-06
o1-2024-12-17
o3-2025-04-16
o4-mini-2025-04-16

resource "azurerm_cognitive_deployment" "gpt-41" {
  count = var.use-azure-ai ? 1 : 0
  cognitive_account_id = azurerm_ai_services.main.id
  name                 = "gpt-4.1-2025-04-14"
  rai_policy_name      = "CustomFilter"
  model {
    format  = "OpenAI"
    name    = "gpt-4.1"
    version = "2025-04-14"
  }
  sku {
    capacity = 5000
    name     = "GlobalStandard"
  }
  depends_on = [
    azapi_resource.content_filter,
  ]
}
*/

resource "azurerm_cognitive_deployment" "gpt-4o-mini" {
  count = var.use-azure-ai ? 1 : 0
  cognitive_account_id   = azurerm_ai_services.main.id
  name                   = "gpt-4o-mini-2024-07-18"
  rai_policy_name        = "CustomFilter"
  version_upgrade_option = "NoAutoUpgrade"
  model {
    format  = "OpenAI"
    name    = "gpt-4o-mini"
    version = "2024-07-18"
  }
  sku {
    capacity = 50000
    name     = "GlobalStandard"
  }
  depends_on = [
    azapi_resource.content_filter,
  ]
}

resource "azurerm_cognitive_deployment" "gpt-4o" {
  count = var.use-azure-ai ? 1 : 0
  cognitive_account_id = azurerm_ai_services.main.id
  name                 = "gpt-4o"
  rai_policy_name      = "CustomFilter"
  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }
  sku {
    capacity = 30000
    name     = "GlobalStandard"
  }
  depends_on = [
    azapi_resource.content_filter,
  ]
}

resource "azurerm_cognitive_deployment" "o3" {
  count = var.use-azure-ai ? 1 : 0
  cognitive_account_id   = azurerm_ai_services.main.id
  name                   = "o3"
  rai_policy_name        = "CustomFilter"
  version_upgrade_option = "NoAutoUpgrade"
  model {
    format  = "OpenAI"
    name    = "o3"
    version = "2025-04-16"
  }
  sku {
    capacity = 10000
    name     = "GlobalStandard"
  }
  depends_on = [
    azapi_resource.content_filter,
  ]
}

resource "azurerm_cognitive_deployment" "o4-mini" {
  count = var.use-azure-ai ? 1 : 0
  cognitive_account_id = azurerm_ai_services.main.id
  name                 = "o4-mini"
  rai_policy_name      = "CustomFilter"
  model {
    format  = "OpenAI"
    name    = "o4-mini"
    version = "2025-04-16"
  }
  sku {
    capacity = 10000
    name     = "GlobalStandard"
  }
  depends_on = [
    azapi_resource.content_filter,
  ]
}

resource "azapi_resource" "content_filter" {
  count = var.use-azure-ai ? 1 : 0
  type      = "Microsoft.CognitiveServices/accounts/raiPolicies@2024-10-01"
  name      = "CustomFilter"
  parent_id = azurerm_ai_services.main.id

  schema_validation_enabled = false

  body = {
    properties = {
      basePolicyName = "Microsoft.Default",
      contentFilters = [
        { name = "hate", blocking = true, enabled = true, severityThreshold = "High", source = "Prompt" },
        { name = "sexual", blocking = true, enabled = true, severityThreshold = "High", source = "Prompt" },
        { name = "selfharm", blocking = true, enabled = true, severityThreshold = "High", source = "Prompt" },
        { name = "violence", blocking = true, enabled = true, severityThreshold = "High", source = "Prompt" },
        { name = "hate", blocking = true, enabled = true, severityThreshold = "High", source = "Completion" },
        { name = "sexual", blocking = true, enabled = true, severityThreshold = "High", source = "Completion" },
        { name = "selfharm", blocking = true, enabled = true, severityThreshold = "High", source = "Completion" },
        { name = "violence", blocking = true, enabled = true, severityThreshold = "High", source = "Completion" },
        // not sure what to call this one
        // { name = "indirect", blocking = false, enabled = false, source = "Prompt" },
        { name = "jailbreak", blocking = false, enabled = false, source = "Prompt" },
        { name = "protected_material_text", blocking = false, enabled = false, source = "Completion" },
        { name = "protected_material_code", blocking = false, enabled = false, source = "Completion" }
      ]
    }
  }
}
