resource "random_pet" "resource-group" {
  prefix = "public"
}

resource "azurerm_resource_group" "main" {
  location = var.region
  name     = random_pet.resource-group.id
}

resource "random_id" "storage-account" {
  byte_length = 8
}

resource "azurerm_storage_account" "main" {
  account_kind                    = "BlockBlobStorage"
  account_replication_type        = "LRS"
  account_tier                    = "Premium"
  allow_nested_items_to_be_public = true
  name                            = random_id.storage-account.hex
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
}

resource "azurerm_storage_container" "files" {
  name                  = "files"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "blob"
}

resource "azurerm_storage_blob" "files" {
  for_each               = fileset("files/", "*")
  name                   = each.value
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.files.name
  type                   = "Block"
  source                 = "files/${each.value}"
}
