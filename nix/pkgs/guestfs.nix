{pkgs}: let
  # Guest-image inspection needs local x86 emulation and virtio, not remote
  # display, audio, smartcard, USB redirection, or disassembly interfaces.
  imageQemu = pkgs.qemu.override {
    hostCpuOnly = true;
    alsaSupport = false;
    pulseSupport = false;
    pipewireSupport = false;
    sdlSupport = false;
    jackSupport = false;
    gtkSupport = false;
    vncSupport = false;
    smartcardSupport = false;
    spiceSupport = false;
    ncursesSupport = false;
    usbredirSupport = false;
    openGLSupport = false;
    rutabagaSupport = false;
    virglSupport = false;
    capstoneSupport = false;
  };
in
  pkgs.libguestfs.override {qemu = imageQemu;}
