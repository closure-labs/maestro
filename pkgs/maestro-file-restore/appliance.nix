{
  pkgs,
  guestfs,
}: let
  inherit (pkgs) lib;
  kernel = pkgs.linux;
  modules = pkgs.makeModulesClosure {
    inherit kernel;
    # Virtio/storage drivers need no hardware firmware blobs.
    firmware = pkgs.runCommand "maestro-restore-firmware" {} "mkdir -p $out/lib/firmware";
    rootModules = ["virtio_pci" "virtio_blk" "virtio_scsi" "virtio_console" "sd_mod" "ext4" "xfs" "btrfs" "vfat" "dm_mod" "fuse"];
    allowMissing = false;
  };
  tools = pkgs.buildEnv {
    name = "maestro-restore-appliance-tools";
    paths = [
      pkgs.coreutils
      pkgs.util-linux
      pkgs.bash
      pkgs.kmod
      pkgs.lvm2
      pkgs.e2fsprogs
      pkgs.xfsprogs
      pkgs.btrfs-progs
      pkgs.dosfstools
      pkgs.ntfs3g
      pkgs.parted
      pkgs.file
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
      pkgs.findutils
    ];
    pathsToLink = ["/bin" "/sbin"];
    ignoreCollisions = true;
  };
  init = pkgs.writeShellScript "maestro-restore-appliance-init" ''
    export PATH=${lib.makeBinPath [tools pkgs.systemd]}:${tools}/sbin
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    mkdir -p /dev/pts /dev/shm /run /tmp /sysroot
    mount -t devpts devpts /dev/pts
    mount -t tmpfs -o mode=1777 tmpfs /dev/shm
    ln -s /proc/self/fd /dev/fd
    mount -t tmpfs tmpfs /run
    ${pkgs.systemd}/lib/systemd/systemd-udevd --daemon
    ${pkgs.systemd}/bin/udevadm trigger --action=add
    ${pkgs.systemd}/bin/udevadm settle
    # Match libguestfs' appliance contract: metadata/device scanning and
    # activation happen only inside this disposable kernel.
    modprobe dm_mod
    modprobe fuse
    mkdir -p /tmp/lvm /run/lock/lvm
    printf 'devices { use_devicesfile = 0 }\n' > /tmp/lvm/lvm.conf
    export LVM_SYSTEM_DIR=/tmp/lvm
    lvm pvscan --cache --activate ay
    # The only control channel is libguestfs' virtio serial RPC connection.
    ${guestfs.guestfsd}/bin/guestfsd
    ${pkgs.busybox}/bin/poweroff -f
  '';
  bootstrap = pkgs.writeShellScript "maestro-restore-appliance-bootstrap" ''
    export PATH=${lib.makeBinPath [pkgs.busybox pkgs.kmod]}
    mkdir -p /proc /sys /dev /newroot
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    export MODPROBE_OPTIONS="-d ${modules}"
    for driver in virtio_pci virtio_blk virtio_scsi virtio_console sd_mod ext4; do
      modprobe "$driver"
    done
    # libguestfs attaches its trusted appliance after the raw data disks.
    # Production always supplies one raw disk. Never search guest labels or
    # UUIDs: a malicious image can duplicate either and supply its own /init.
    restore_root=/dev/sdb
    for parameter in $(cat /proc/cmdline); do
      case "$parameter" in
        maestro_restore_root=/dev/sd[a-z]) restore_root="''${parameter#*=}" ;;
      esac
    done
    for attempt in $(seq 1 100); do
      if mount -t ext4 "$restore_root" /newroot 2>/dev/null; then break; fi
      sleep 0.1
    done
    test -x /newroot/init || exit 1
    umount /dev /sys /proc
    exec switch_root /newroot /init
  '';
  initrd = pkgs.makeInitrd {
    name = "maestro-restore-bootstrap";
    contents = [
      {
        object = bootstrap;
        symlink = "/init";
      }
    ];
  };
  closure = pkgs.closureInfo {rootPaths = [init tools modules pkgs.systemd guestfs.guestfsd];};
in
  pkgs.runCommand "maestro-restore-appliance" {
    nativeBuildInputs = [pkgs.e2fsprogs];
    passthru = {inherit kernel guestfs;};
  } ''
    mkdir -p rootfs/nix/store rootfs/etc rootfs/proc rootfs/sys rootfs/dev rootfs/run rootfs/tmp rootfs/sysroot rootfs/lib $out/nix-support
    while IFS= read -r path; do cp -a "$path" rootfs/nix/store/; done < ${closure}/store-paths
    ln -s ${init} rootfs/init
    ln -s ${tools}/bin rootfs/bin
    ln -s ${tools}/sbin rootfs/sbin
    ln -s ${modules}/lib/modules rootfs/lib/modules
    ln -s /proc/mounts rootfs/etc/mtab
    printf 'root:x:0:0:root:/root:/bin/bash\n' > rootfs/etc/passwd
    printf 'root:x:0:\n' > rootfs/etc/group
    touch rootfs/etc/fstab
    chmod 1777 rootfs/tmp
    bytes=$(du -sb rootfs | cut -f1)
    truncate -s "$((bytes * 2 + 67108864))" $out/root
    mkfs.ext4 -q -F -L guestfs_root -d rootfs $out/root
    ln -s ${kernel}/bzImage $out/kernel
    ln -s ${initrd}/initrd $out/initrd
    printf 'Maestro fixed appliance built entirely from locked Nix sources.\n' > $out/README.fixed
    # Keep embedded userspace in the host closure and its source-bound SBOM.
    cp ${closure}/store-paths $out/nix-support/guest-closure
  ''
