{pkgs}: let
  inherit (pkgs) lib;
  qemu = pkgs.qemu.override {
    hostCpuTargets = ["x86_64-softmmu"];
    minimal = true;
    enableBlobs = true;
    enableTools = true;
    seccompSupport = true;
    numaSupport = false;
  };
  mkGuestfs = appliance:
    (pkgs.libguestfs.override {inherit qemu appliance;}).overrideAttrs (old: {
      configureFlags = old.configureFlags ++ ["--without-libvirt" "--with-default-backend=direct"];
    });
  baseGuestfs = mkGuestfs null;
  appliance = import ./appliance.nix {
    inherit pkgs;
    guestfs = baseGuestfs;
  };
  guestfs = mkGuestfs appliance;
  python = pkgs.python3;
in
  pkgs.writeShellApplication {
    name = "maestro-file-restore";
    runtimeInputs = [pkgs.coreutils pkgs.util-linux];
    text = ''
      export LIBGUESTFS_PATH=${appliance}
      export LIBGUESTFS_BACKEND=direct
      export LIBGUESTFS_BACKEND_SETTINGS=force_tcg
      export LIBGUESTFS_HV=${qemu}/bin/qemu-system-x86_64
      export PYTHONPATH=${guestfs}/${pkgs.python3.sitePackages}
      # One bounded appliance per service account; the lock survives exec and
      # is released on every exit, cancellation and timeout.
      exec 9>"''${TMPDIR:?}/maestro-file-restore.lock"
      flock --exclusive --nonblock 9 || { echo 'file restore is busy' >&2; exit 75; }
      exec timeout --signal=TERM --kill-after=10s 15m \
        setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all \
        ${python}/bin/python3 ${./restore.py} "$@"
    '';
    passthru = {inherit appliance guestfs qemu;};
    meta.description = "Read-only XO file restore through a bounded unprivileged guest-kernel appliance";
  }
