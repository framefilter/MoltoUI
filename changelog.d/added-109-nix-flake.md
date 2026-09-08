- **Nix flake.** The repository now builds as a flake: `keyroost` (the
  default package), `keyroostctl`, and a development shell, with the GUI's
  X11/Wayland libraries wired into the binary's rpath on Linux. Tested on
  x86_64 Linux. Contributed by @MakeShiftArtist. ([#109])
