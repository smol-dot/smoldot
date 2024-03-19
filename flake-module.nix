{ self, ... }: {
  perSystem = { config, self', inputs', pkgs, system, ... }:
    let craneLib = self.inputs.crane.lib.${system};
    in {
      packages = rec {
        # starting nix reproducible determinsic isolated builds
        # so we start from simple thing, build and cache dependnecies once
        # next step could be to build full node, and next run connect full node via nix
        default =
          craneLib.buildDepsOnly { src = craneLib.cleanCargoSource ./.; };
      };
    };
}
