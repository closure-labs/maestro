{...}: {
  maestro.ci.targets = builtins.fromJSON ''
    {"checks-x86_64-linux-packer-policy":{"owner":"features/xcp-ng/template","attribute":"checks.x86_64-linux.packer-policy","name":"packer-policy","phases":["validation"],"order":{"validation":18},"dependencies":[],"requirements":["deterministic"]},"packages-x86_64-linux-deploy-template":{"owner":"features/xcp-ng/template","attribute":"packages.x86_64-linux.deploy-template","name":"deploy-template","phases":["publish"],"order":{"publish":3},"dependencies":[],"requirements":["deterministic"]}}
  '';
}
