# A retained boot is valid only for these exact execution and evidence verifiers.
builtins.hashString "sha256" (builtins.concatStringsSep "\n" (map (builtins.hashFile "sha256") [
  ../_source/boot-media.sh
  ../_source/boot-evidence.py
  ../_source/verify-inventory.sh
  ../_source/verify-state.sh
  ../_source/validate-state.sh
  ../_source/qualification-state.schema.json
  ../../../ci/graph/_source/bindings.py
  ../../../ci/graph/_source/transfer.py
]))
