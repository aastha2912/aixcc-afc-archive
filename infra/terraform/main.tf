resource "random_pet" "resource-group" {
  prefix = "tf"
}

resource "azurerm_resource_group" "main" {
  location = var.region
  name     = coalesce(var.resource-group, random_pet.resource-group.id)
}

output "resource_group" {
  value = azurerm_resource_group.main.name
}

locals {
  user_data = (base64encode(templatefile("user-data.yml", {
    ADMIN_USERNAME      = var.admin-username
    CRS_RESOURCE_GROUP  = azurerm_resource_group.main.name
    CRS_BLOB_ENDPOINT   = "https://${azurerm_storage_account.main.name}.blob.core.windows.net"
    CRS_STORAGE_ACCOUNT = azurerm_storage_account.main.name
    CRS_BUILDER_COUNT   = var.build-count
    CRS_FUZZER_COUNT    = var.fuzz-count
    CRS_INFER_URL       = var.infer-url
    CRS_DEV_BLOB_URL    = var.dev-blob-url
    CRS_DEV_SAS_KEY     = var.dev-sas-token
    CRS_REGISTRY_NAME   = azurerm_container_registry.main.name
    CRS_REGISTRY_DOMAIN = "${azurerm_container_registry.main.name}.azurecr.io"
    CRS_REPO_HASH       = local.repo-hash
    CRS_AZ_OAI_ENDPOINT = coalesce(var.az-oai-endpoint, azurerm_ai_services.main.endpoint)
    CRS_AZ_OAI_KEY      = coalesce(var.az-oai-key, azurerm_ai_services.main.primary_access_key)

    CAPI_URL   = var.capi-url
    CAPI_ID    = var.capi-id
    CAPI_TOKEN = var.capi-token

    CRS_MODEL     = var.crs-model
    CRS_MODEL_MAP = var.crs-model-map

    API_KEY_ID    = var.api-key-id
    API_KEY_TOKEN = var.api-key-token

    OTEL_EXPORTER_OTLP_ENDPOINT = var.otel-url
    OTEL_EXPORTER_OTLP_HEADERS  = var.otel-headers

    TAILSCALE_HOSTNAME = var.tailscale-hostname
    TAILSCALE_TAGS     = var.tailscale-tags
  })))

  zone = var.zone != "" ? var.zone : null
}

data "azurerm_client_config" "current" {}

// secrets
resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "azurerm_ssh_public_key" "main" {
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  name                = "main-key"
  public_key          = tls_private_key.ssh.public_key_openssh
}

// blob storage
resource "random_id" "crs-storage-account" {
  byte_length = 8
}

output "crs_storage_account" {
  value = random_id.crs-storage-account.hex
}

resource "azurerm_storage_account" "main" {
  account_kind                    = "BlockBlobStorage"
  account_replication_type        = "LRS"
  account_tier                    = "Premium"
  allow_nested_items_to_be_public = false
  name                            = random_id.crs-storage-account.hex
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
}

resource "azurerm_storage_container" "crs" {
  name                  = "crs"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "infra" {
  name                  = "infra"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "secrets" {
  name                  = "secrets"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "backup" {
  name                  = "backup"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

// upload initial artifacts
data "external" "git-dir" {
  program = ["bash", "-c", "git rev-parse --git-dir | jq -R '{path: .}'"]
}

data "external" "repo-hash" {
  program = [
    "bash",
    "-c",
    <<EOT
    repo_hash=$((git rev-parse HEAD; echo '||'; git diff HEAD) | shasum -a 256 | awk '{print $1}');
    mkdir -p "${path.module}/files";
    git diff HEAD > "${path.module}/files/repo-$repo_hash.diff";
    echo "$repo_hash" | jq -R '{hash: .}'
    EOT
  ]
}

locals {
  repo-hash      = data.external.repo-hash.result.hash
  repo-tar-name  = "repo-${local.repo-hash}.tar.gz"
  repo-diff-name = "repo-${local.repo-hash}.diff"
}

resource "archive_file" "repo" {
  type        = "tar.gz"
  source_dir  = data.external.git-dir.result.path
  output_path = "${path.module}/files/${local.repo-tar-name}"
}

resource "azurerm_storage_blob" "repo-tar" {
  name                   = "repo.tar.gz"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.infra.name
  type                   = "Block"
  source                 = "${path.module}/files/${local.repo-tar-name}"
}

resource "azurerm_storage_blob" "repo-diff" {
  name                   = "repo.diff"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.infra.name
  type                   = "Block"
  source_content         = file("${path.module}/files/${local.repo-diff-name}")
}

resource "azurerm_storage_blob" "infer-tar" {
  count                  = (var.infer-path != "") ? 1 : 0
  name                   = "infer.tar.xz"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.infra.name
  type                   = "Block"
  source                 = var.infer-path
}

locals {
  tokens-dir = coalesce(var.tokens-dir, "${path.module}/../../tokens_etc")
  tokens-tar = "${path.module}/files/tokens.tar.gz"
}

resource "archive_file" "tokens" {
  type        = "tar.gz"
  source_dir  = local.tokens-dir
  output_path = local.tokens-tar
}

resource "azurerm_storage_blob" "tokens-tar" {
  name                   = "tokens.tar.gz"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.secrets.name
  type                   = "Block"
  source                 = local.tokens-tar
}

resource "azurerm_storage_blob" "ssh-privkey" {
  name                   = "ssh_privkey"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.secrets.name
  type                   = "Block"
  source_content         = tls_private_key.ssh.private_key_openssh
}

resource "azurerm_storage_blob" "tailscale-secret" {
  count                  = (var.tailscale-secret != "") ? 1 : 0
  name                   = "tailscale_secret"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.secrets.name
  type                   = "Block"
  source_content         = var.tailscale-secret
}

resource "null_resource" "upload" {
  depends_on = [
    resource.azurerm_storage_blob.repo-tar,
    resource.azurerm_storage_blob.repo-diff,
    resource.azurerm_storage_blob.infer-tar,
    resource.azurerm_storage_blob.tokens-tar,
    resource.azurerm_storage_blob.ssh-privkey,
    resource.azurerm_storage_blob.tailscale-secret,
  ]
}

// network
resource "azurerm_virtual_network" "main" {
  address_space       = ["10.0.0.0/8"]
  name                = "crs-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}
resource "azurerm_subnet" "crs" {
  address_prefixes     = ["10.0.0.0/16"]
  name                 = "crs"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
}
resource "azurerm_subnet" "azure" {
  address_prefixes     = ["10.1.0.0/24"]
  name                 = "azure"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
}

// security groups
resource "azurerm_network_security_group" "crs" {
  name                = "crs-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "ICMP"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Icmp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  depends_on = [
    resource.azurerm_network_interface.crs,
    resource.azurerm_network_interface.build,
    resource.azurerm_network_interface.fuzz,
  ]
}

// network interfaces
resource "random_id" "crs-ip" {
  byte_length = 8
}

resource "azurerm_public_ip" "crs" {
  allocation_method       = "Static"
  idle_timeout_in_minutes = 15
  name                    = random_id.crs-ip.hex
  zones                   = var.zone != "" ? [var.zone] : null
  location                = azurerm_resource_group.main.location
  resource_group_name     = azurerm_resource_group.main.name
}

output "crs_ip" {
  value = azurerm_public_ip.crs.ip_address
}

resource "azurerm_network_interface" "crs" {
  name                           = "crs"
  location                       = azurerm_resource_group.main.location
  resource_group_name            = azurerm_resource_group.main.name
  accelerated_networking_enabled = true

  ip_configuration {
    name                          = "internal"
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.0.10"
    subnet_id                     = azurerm_subnet.crs.id
    public_ip_address_id          = azurerm_public_ip.crs.id
  }
}

resource "azurerm_network_interface" "build" {
  count = var.build-count

  name                           = "build-${count.index}"
  location                       = azurerm_resource_group.main.location
  resource_group_name            = azurerm_resource_group.main.name
  accelerated_networking_enabled = true

  ip_configuration {
    name = "internal"
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.2.${10 + count.index}"
    subnet_id                     = azurerm_subnet.crs.id
  }
}

resource "azurerm_network_interface" "fuzz" {
  count = var.fuzz-count

  name                           = "fuzz-${count.index}"
  location                       = azurerm_resource_group.main.location
  resource_group_name            = azurerm_resource_group.main.name
  accelerated_networking_enabled = true

  ip_configuration {
    name = "internal"
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.3.${10 + count.index}"
    subnet_id                     = azurerm_subnet.crs.id
  }
}

// security group associations
resource "azurerm_network_interface_security_group_association" "crs" {
  network_interface_id      = azurerm_network_interface.crs.id
  network_security_group_id = azurerm_network_security_group.crs.id
}

resource "azurerm_network_interface_security_group_association" "build" {
  for_each                  = { for idx, iface in azurerm_network_interface.build : idx => iface }
  network_interface_id      = each.value.id
  network_security_group_id = azurerm_network_security_group.crs.id
}

resource "azurerm_network_interface_security_group_association" "fuzz" {
  for_each                  = { for idx, iface in azurerm_network_interface.fuzz : idx => iface }
  network_interface_id      = each.value.id
  network_security_group_id = azurerm_network_security_group.crs.id
}

// virtual machines
resource "azurerm_virtual_machine" "crs" {
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  name                  = "crs"
  network_interface_ids = [azurerm_network_interface.crs.id]
  vm_size               = coalesce(var.crs-instance-type, var.instance-type)
  zones                 = local.zone != null ? [local.zone] : null
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.crs-identity.id]
  }
  os_profile {
    computer_name  = "crs"
    admin_username = var.admin-username
    custom_data    = local.user_data
  }
  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/${var.admin-username}/.ssh/authorized_keys"
      key_data = azurerm_ssh_public_key.main.public_key
    }
  }
  storage_os_disk {
    name              = "crs-os"
    caching           = "ReadWrite"
    managed_disk_type = "Premium_LRS"
    create_option     = "FromImage"
  }
  storage_data_disk {
    name              = "crs-data"
    managed_disk_type = "Premium_LRS"
    create_option     = "Empty"
    disk_size_gb      = "1000"
    caching           = "ReadWrite"
    lun               = 1
  }
  storage_image_reference {
    offer     = "ubuntu-24_04-lts"
    publisher = "canonical"
    sku       = "server"
    version   = "latest"
  }
  depends_on = [
    resource.null_resource.upload,
    resource.null_resource.role_assignments,
  ]
}

resource "azurerm_virtual_machine" "build" {
  count                 = var.build-count
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  name                  = "build-${count.index}"
  network_interface_ids = [azurerm_network_interface.build[count.index].id]
  vm_size               = coalesce(var.build-instance-type, var.instance-type)
  zones                 = local.zone != null ? [local.zone] : null
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.worker-identity.id]
  }
  os_profile {
    computer_name  = "build-${count.index}"
    admin_username = var.admin-username
    custom_data    = local.user_data
  }
  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/${var.admin-username}/.ssh/authorized_keys"
      key_data = azurerm_ssh_public_key.main.public_key
    }
  }
  storage_os_disk {
    name              = "build-${count.index}-os"
    caching           = "ReadWrite"
    managed_disk_type = "Premium_LRS"
    create_option     = "FromImage"
  }
  storage_data_disk {
    name              = "build-${count.index}-data"
    managed_disk_type = "Premium_LRS"
    create_option     = "Empty"
    disk_size_gb      = "1000"
    caching           = "ReadWrite"
    lun               = 1
  }
  storage_image_reference {
    offer     = "ubuntu-24_04-lts"
    publisher = "canonical"
    sku       = "server"
    version   = "latest"
  }
  depends_on = [
    resource.null_resource.upload,
    resource.null_resource.role_assignments,
  ]
}

resource "azurerm_virtual_machine" "fuzz" {
  count                 = var.fuzz-count
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  name                  = "fuzz-${count.index}"
  network_interface_ids = [azurerm_network_interface.fuzz[count.index].id]
  vm_size               = coalesce(var.fuzz-instance-type, var.instance-type)
  zones                 = local.zone != null ? [local.zone] : null
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.worker-identity.id]
  }
  os_profile {
    computer_name  = "fuzz-${count.index}"
    admin_username = var.admin-username
    custom_data    = local.user_data
  }
  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/${var.admin-username}/.ssh/authorized_keys"
      key_data = azurerm_ssh_public_key.main.public_key
    }
  }
  storage_os_disk {
    name              = "fuzz-${count.index}-os"
    caching           = "ReadWrite"
    managed_disk_type = "Premium_LRS"
    create_option     = "FromImage"
  }
  storage_data_disk {
    name              = "fuzz-${count.index}-data"
    managed_disk_type = "Premium_LRS"
    create_option     = "Empty"
    disk_size_gb      = "1000"
    caching           = "ReadWrite"
    lun               = 1
  }
  storage_image_reference {
    offer     = "ubuntu-24_04-lts"
    publisher = "canonical"
    sku       = "server"
    version   = "latest"
  }
  depends_on = [
    resource.null_resource.upload,
    resource.null_resource.role_assignments,
  ]
}

locals {
  main_vms = [azurerm_virtual_machine.crs]
  worker_vms = concat(
    azurerm_virtual_machine.build,
    azurerm_virtual_machine.fuzz,
  )
  all_vms = concat(
    local.main_vms,
    local.worker_vms,
  )
}

// ambient auth from vm
resource "azurerm_user_assigned_identity" "crs-identity" {
  name                = "crs-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}
resource "azurerm_user_assigned_identity" "worker-identity" {
  name                = "worker-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_role_assignment" "crs-self-rg" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.crs-identity.principal_id
}
resource "azurerm_role_assignment" "crs-storage-access" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.crs-identity.principal_id
}
resource "azurerm_role_assignment" "crs-dev-storage" {
  count                = var.grant-dev-storage ? 1 : 0
  scope                = "/subscriptions/cb3c835a-f42b-4828-bfec-d8c51d86f256/resourceGroups/public-feasible-gull/providers/Microsoft.Storage/storageAccounts/de6543ab956de244"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.crs-identity.principal_id
}

resource "azurerm_role_assignment" "worker-storage-crs" {
  scope                = azurerm_storage_container.crs.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.worker-identity.principal_id
}
resource "azurerm_role_assignment" "worker-storage-infra" {
  scope                = azurerm_storage_container.infra.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.worker-identity.principal_id
}

// grants storage access to the user running this command
resource "azurerm_role_assignment" "storage-user" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

// container registry
resource "random_id" "crs-registry" {
  byte_length = 8
}

output "crs_registry" {
  value = azurerm_container_registry.main.name
}

resource "azurerm_container_registry" "main" {
  name                = random_id.crs-registry.hex
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Premium"
  admin_enabled       = false
}

resource "azurerm_private_dns_zone" "acr_private_dns_zone" {
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "acr_private_dns_zone_virtual_network_link" {
  name                  = "${azurerm_container_registry.main.name}-private-dns-zone-vnet-link"
  private_dns_zone_name = azurerm_private_dns_zone.acr_private_dns_zone.name
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_id    = azurerm_virtual_network.main.id
}

resource "azurerm_private_endpoint" "acr_private_endpoint" {
  name                = "${azurerm_container_registry.main.name}-private-endpoint"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.azure.id

  private_service_connection {
    name                           = "${azurerm_container_registry.main.name}-service-connection"
    private_connection_resource_id = azurerm_container_registry.main.id
    is_manual_connection           = false
    subresource_names = [
      "registry"
    ]
  }

  private_dns_zone_group {
    name = "${azurerm_container_registry.main.name}-private-dns-zone-group"

    private_dns_zone_ids = [
      azurerm_private_dns_zone.acr_private_dns_zone.id
    ]
  }
}

resource "azurerm_role_assignment" "acr-crs" {
  scope                = azurerm_container_registry.main.id
  principal_id         = azurerm_user_assigned_identity.crs-identity.principal_id
  role_definition_name = "AcrPush"
}
resource "azurerm_role_assignment" "acr-worker" {
  scope                = azurerm_container_registry.main.id
  principal_id         = azurerm_user_assigned_identity.worker-identity.principal_id
  role_definition_name = "AcrPush"
}

resource "null_resource" "role_assignments" {
  depends_on = [
    resource.azurerm_role_assignment.crs-storage-access,
    resource.azurerm_role_assignment.worker-storage-crs,
    resource.azurerm_role_assignment.worker-storage-infra,
    resource.azurerm_role_assignment.acr-crs,
    resource.azurerm_role_assignment.acr-worker,
  ]
}
