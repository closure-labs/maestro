locals {
  timestamp  = regex_replace(timestamp(), "[- TZ:]", "")
  build_date = formatdate("YYYY-MM-DD", timestamp())

  vm_name = coalesce(
    var.vm_name,
    "maestro-${local.timestamp}",
  )
  vm_description = coalesce(
    var.vm_description,
    "[Template] Maestro NixOS appliance with NoCloud support; built ${local.build_date} by Packer",
  )
}

source "xenserver-iso" "maestro" {
  iso_url        = var.iso_url
  iso_checksum   = var.iso_checksum
  sr_iso_name    = var.sr_iso_name
  sr_name        = var.sr_name
  tools_iso_name = ""

  remote_host     = var.remote_host
  remote_username = var.remote_username
  remote_password = var.remote_password

  clone_template = var.clone_template
  firmware       = "uefi"

  vm_name         = local.vm_name
  vm_description  = local.vm_description
  vm_tags         = var.vm_tags
  vcpus_max       = var.vcpus
  vcpus_atstartup = var.vcpus
  vm_memory       = var.memory_mb
  disk_name       = "${local.vm_name}-disk0"
  disk_size       = var.disk_size_mb
  network_names   = var.network_names

  boot_wait = "10s"
  boot_command = [
    "<enter><wait60>",
    "sudo maestro-enroll-bootstrap-key ${var.bootstrap_public_key_b64}<enter>",
  ]
  install_timeout = var.install_timeout
  ip_getter       = "tools"

  # Only the public key enters the console; the private key stays on the builder.
  ssh_username           = "maestro"
  ssh_private_key_file   = var.bootstrap_private_key_file
  ssh_wait_timeout       = var.ssh_wait_timeout
  ssh_handshake_attempts = var.ssh_handshake_attempts

  output_directory     = "${path.root}/output/${local.timestamp}"
  keep_vm              = "on_success"
  skip_set_template    = false
  format               = "none"
  export_network_names = var.export_network_names
}
