variable "subscription-id" {
  description = "Azure Subscription ID"
  type        = string
  default     = "cb3c835a-f42b-4828-bfec-d8c51d86f256"
}

variable "resource-group" {
  description = "Azure Resource Group"
  type        = string
  default     = ""
}

variable "region" {
  description = "Azure Region"
  type        = string
  default     = "westus"
}

variable "zone" {
  description = "Azure Zone"
  type        = string
  default     = ""
}

variable "instance-type" {
  description = "Azure instance type"
  type        = string
  default     = "Standard_L8as_v3"
}

variable "crs-instance-type" {
  description = "Azure instance type (CRS override)"
  type        = string
  default     = ""
}

variable "build-instance-type" {
  description = "Azure instance type (Build override)"
  type        = string
  default     = ""
}

variable "fuzz-instance-type" {
  description = "Azure instance type (Fuzz override)"
  type        = string
  default     = ""
}

variable "build-count" {
  description = "Build machine count"
  type        = number
  default     = 1
}

variable "fuzz-count" {
  description = "Fuzzing machine count"
  type        = number
  default     = 1
}

variable "admin-username" {
  description = "admin/ssh username"
  type        = string
  default     = "team"
}

variable "tokens-dir" {
  description = "local tokens_etc directory"
  type        = string
  default     = ""
}

variable "infer-path" {
  description = "local path to infer tarball"
  type        = string
  default     = ""
}

variable "infer-url" {
  description = "url to infer tarball"
  type        = string
  default     = "https://de6543ab956de244.blob.core.windows.net/files/infer_2232d6b.tar.xz"
}

variable "tailscale-secret" {
  description = "tailscale secret key"
  type        = string
  default     = ""
}

variable "tailscale-hostname" {
  description = "tailscale hostname"
  type        = string
  default     = ""
}

variable "tailscale-tags" {
  description = "tailscale tags"
  type        = string
  default     = ""
}

variable "capi-url" {
  description = "Competition API URL"
  type        = string
  default     = ""
}

variable "capi-id" {
  description = "Competition Key ID"
  type        = string
  default     = ""
}

variable "capi-token" {
  description = "Competition Key Token"
  type        = string
  default     = ""
}

variable "api-key-id" {
  description = "CRS Basic Auth ID"
  type        = string
  default     = ""
}

variable "api-key-token" {
  description = "CRS Basic Auth Token"
  type        = string
  default     = ""
}

variable "otel-url" {
  description = "OTEL Export URL"
  type        = string
  default     = ""
}

variable "otel-headers" {
  description = "OTEL Export Headers"
  type        = string
  default     = ""
}

variable "crs-model" {
  description = "Default model to use"
  type        = string
  default     = "claude-3-5-sonnet-20241022"
}

variable "crs-model-map" {
  description = "Default model map to use"
  type        = string
  default     = "/crs/configs/models-anthropic.toml"
}

variable "dev-blob-url" {
  description = "Base url for dev account blob storage that we will mirror"
  type        = string
  default     = "https://de6543ab956de244.blob.core.windows.net"
}

variable "dev-sas-token" {
  description = "SAS token to access dev blob storage for copying"
  type        = string
  default     = "sv=2024-11-04&ss=b&srt=sco&sp=rlacitf&se=2026-04-26T01:19:49Z&st=2025-04-25T17:19:49Z&spr=https&sig=78H6p%2FkFGPuQrTJLWYFKw7s7cBuqQcFlm4oKj1DjzmU%3D"
}

variable "use-azure-ai" {
  description = "Deploy Azure AI models"
  type        = bool
  default     = false
}

variable "grant-dev-storage" {
  description = "Grant crs read/write access to dev storage bucket"
  type        = bool
  default     = false
}

variable "az-oai-endpoint" {
  description = "optional azure oai endpoint"
  type        = string
  default     = ""
}

variable "az-oai-key" {
  description = "optional azure oai key"
  type        = string
  default     = ""
}