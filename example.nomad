job "example" {
  datacenters = ["dc1"]
  type        = "service"

  group "application" {
    count = 1

    task "backend" {
      driver = "firecracker"

      config {
        image_path = "/root/hello-rootfs.ext4"
        kernel_path = "/root/hello-vmlinux.bin"
        kernel_boot_args = "ro console=ttyS0 noapic reboot=k panic=1 pci=off nomodules"
      }
    }
  }
}
