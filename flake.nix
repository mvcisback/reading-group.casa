{
  description = "Nix development shell for reading-group";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };
    nix2container = {
      url = "github:nlewo/nix2container";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
    };
  };

  outputs = inputs@{ nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        python = pkgs.python311;
        workspaceRoot = ./.;
        workspace = inputs.uv2nix.lib.workspace.loadWorkspace {
          workspaceRoot = workspaceRoot;
        };
        overlay = workspace.mkPyprojectOverlay {
          sourcePreference = "wheel";
        };
        baseSet = pkgs.callPackage inputs.pyproject-nix.build.packages {
          inherit python;
        };
        pythonSet = baseSet.overrideScope (
          pkgs.lib.composeManyExtensions [
            inputs.pyproject-build-systems.overlays.default
            overlay
          ]
        );
        venv = pythonSet.mkVirtualEnv "reading-group-venv" workspace.deps.default;
        server = pkgs.writeShellScriptBin "reading-group-server" ''
          cd ${workspaceRoot}
          export PYTHONPATH=${workspaceRoot}
          exec ${venv}/bin/python main.py "$@"
        '';
        cli = pkgs.writeShellScriptBin "reading-group-cli" ''
          cd ${workspaceRoot}
          export PYTHONPATH=${workspaceRoot}
          exec ${venv}/bin/python cli.py "$@"
        '';
        serverApp = {
          type = "app";
          program = "${server}/bin/reading-group-server";
        };
        cliApp = {
          type = "app";
          program = "${cli}/bin/reading-group-cli";
        };
        nix2containerPkgs = inputs.nix2container.packages.${system};
        appSource = pkgs.runCommand "reading-group-app-source" {} ''
          mkdir -p $out/app
          cp -R ${workspaceRoot}/. $out/app
          rm -rf $out/app/.git
          mkdir -p $out/data
        '';
        containerImage = nix2containerPkgs.nix2container.buildImage {
          name = "reading-group-server";
          tag = "latest";
          config = {
            workingDir = "/app";
            env = [
              "PYTHONPATH=/app"
              "READING_GROUP_DB=/data/reading_group.db"
            ];
            cmd = [
              "${venv}/bin/python"
              "main.py"
              "--host"
              "0.0.0.0"
              "--port"
              "8000"
              "--db-path"
              "/data/reading_group.db"
              "--no-reload"
            ];
            exposedPorts = {
              "8000/tcp" = {};
            };
          };
          copyToRoot = appSource;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.uv
            pkgs.mermaid-cli
            pkgs.commitizen
            venv
          ];
          shellHook = ''
            export PYTHONPATH=${workspaceRoot}
          '';
        };
        packages = {
          readingGroupServerImage = containerImage;
        };
        apps = {
          default = serverApp;
          server = serverApp;
          cli = cliApp;
        };
      });
}
