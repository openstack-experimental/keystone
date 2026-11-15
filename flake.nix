# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Development environment for the IAM implementation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Pinned to the workspace MSRV (`rust-version` in Cargo.toml) so that
        # `nix flake update` cannot silently pull in new clippy lints. Bump
        # together with the MSRV.
        rustVersion = "1.96.0";
        rustToolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Keep the tree minus VCS, build output and files that never affect
        # the build (docs, CI, Nix files), so editing those does not rebuild
        # the workspace. Non-Rust files (`.proto`, OAuth2 templates, Rego
        # policies, fixtures) must stay, so crane's Rust-only filter is not
        # used.
        rootPath = toString ./.;
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            let
              rel = pkgs.lib.removePrefix "${rootPath}/" (toString path);
              base = baseNameOf path;
            in
            !(
              builtins.elem base [
                "target"
                "result"
                ".direnv"
                ".git"
              ]
              || builtins.elem rel [
                "doc"
                ".github"
                "nix"
                "flake.nix"
                "flake.lock"
                ".envrc"
              ]
            );
          name = "keystone-source";
        };

        # Native tooling for the crates that need it: `protoc` for
        # `crates/storage/build.rs`, plus cmake/clang for aws-lc.
        commonArgs = {
          inherit src;
          strictDeps = true;
          pname = "keystone";
          version = "0.0.0";
          nativeBuildInputs = with pkgs; [
            pkg-config
            protobuf
            cmake
            clang
          ];
          buildInputs = with pkgs; [
            openssl
            zlib
            # `storage-crypto-tpm` links tss2-sys via tss-esapi-sys.
            tpm2-tss
          ];
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          # The build script only auto-detects /usr/include.
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        };

        # The deliverables are the `keystone` and `keystone-manage` binaries
        # with default features, so their dependency build is scoped to those
        # two packages instead of the whole workspace (skips the TPM, pkcs11
        # and test-only dependencies).
        packageArgs = "--locked -p openstack-keystone -p openstack-keystone-cli-manage";

        mkKeystone =
          {
            lto,
            features ? "",
          }:
          let
            args = commonArgs // {
              cargoExtraArgs = packageArgs + pkgs.lib.optionalString (features != "") " --features ${features}";
              # Same overrides for the dependency build and the package, so
              # the cached dependencies are reused.
              CARGO_PROFILE_RELEASE_LTO = if lto then "thin" else "false";
              CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
              # Unit tests run in `checks.nextest`.
              doCheck = false;
            };
          in
          craneLib.buildPackage (
            args
            // {
              cargoArtifacts = craneLib.buildDepsOnly args;
              meta = {
                description = "OpenStack Keystone Rust implementation";
                license = pkgs.lib.licenses.asl20;
                mainProgram = "keystone";
              };
            }
          );

        # Fast build without LTO, same as the `skaffold` profile.
        keystone = mkKeystone { lto = false; };
        # Thin LTO, matching `[profile.release]` in Cargo.toml.
        keystone-release = mkKeystone { lto = true; };

        # Server for the VM test: sqlite + in-process regorus policy + WASM
        # auth plugins, as built by `tools/start-api.sh`.
        keystone-vm = mkKeystone {
          lto = false;
          features = "openstack-keystone/wasm_plugins,openstack-keystone/sqlite,openstack-keystone/regorus";
        };

        # ADR 0025 reference auth plugin (standalone wasm32 crate).
        wasmToolchain = pkgs.rust-bin.stable.${rustVersion}.minimal.override {
          targets = [ "wasm32-unknown-unknown" ];
        };
        craneWasm = (crane.mkLib pkgs).overrideToolchain wasmToolchain;
        pluginSrc = ./crates/auth-plugin-runtime/tests/fixtures/reference-plugin;
        pluginArgs = {
          src = pluginSrc;
          strictDeps = true;
          pname = "reference-plugin";
          version = "0.1.0";
          CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          doCheck = false;
        };
        referencePlugin = craneWasm.buildPackage (
          pluginArgs
          // {
            cargoArtifacts = craneWasm.buildDepsOnly pluginArgs;
            installPhaseCommand = ''
              mkdir -p $out
              cp target/wasm32-unknown-unknown/release/reference_plugin.wasm $out/
            '';
          }
        );

        # Pre-built `test_api` nextest archive, run inside the VM. The
        # suites have `test = false`, so each must be named with `--test`.
        apiTestArgs = "-p test_api --test integration_api_v3 --test integration_api_v4 --test scim_v2";
        apiDeps = craneLib.buildDepsOnly (
          commonArgs
          // {
            cargoExtraArgs = "--locked ${apiTestArgs}";
            cargoCheckCommand = "true";
            # crane appends cargoExtraArgs to this command.
            cargoBuildCommand = "cargo build --tests";
            doCheck = false;
          }
        );
        apiArchive = craneLib.mkCargoDerivation (
          commonArgs
          // {
            pname = "keystone-api-tests";
            cargoArtifacts = apiDeps;
            doInstallCargoArtifacts = false;
            nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-nextest ];
            buildPhaseCargoCommand = "cargo nextest archive --locked ${apiTestArgs} --archive-file archive.tar.zst";
            installPhaseCommand = "mkdir -p $out && cp archive.tar.zst $out/";
          }
        );

        # Checks need the whole workspace, in the dev profile (clippy and
        # nextest do not compile in release). Built lazily: only
        # `nix flake check` pays for it.
        checkArgs = commonArgs // {
          CARGO_PROFILE = "dev";
        };
        checkArtifacts = craneLib.buildDepsOnly (
          checkArgs
          // {
            cargoExtraArgs = "--workspace --locked";
          }
        );

        # Workspace members that need live services (Postgres, SPIRE, OPA,
        # IdPs) and cannot run in the Nix sandbox. They are still linted
        # (clippy only compiles them), but not run by nextest.
        serviceTests = [
          "test_api"
          "test_integration"
          "test_federation"
        ];
        excludeServiceTests = pkgs.lib.concatMapStringsSep " " (p: "--exclude ${p}") serviceTests;
      in
      {
        packages = {
          default = keystone;
          inherit keystone keystone-release keystone-vm;
          reference-plugin = referencePlugin;
          api-tests = apiArchive;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Live-server API suite in a NixOS VM (needs KVM). Heavy, so a
          # package rather than a flake check: `nix build .#vm-api-test`.
          vm-api-test = import ./nix/vm-api-test.nix {
            inherit
              pkgs
              src
              referencePlugin
              apiArchive
              ;
            keystone = keystone-vm;
          };
        };

        apps.default = flake-utils.lib.mkApp {
          drv = keystone;
          name = "keystone";
        };
        apps.keystone-manage = flake-utils.lib.mkApp {
          drv = keystone;
          name = "keystone-manage";
        };

        checks = {
          fmt = craneLib.cargoFmt {
            inherit (commonArgs) pname version;
            inherit src;
          };

          clippy = craneLib.cargoClippy (
            checkArgs
            // {
              cargoArtifacts = checkArtifacts;
              cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
            }
          );

          nextest = craneLib.cargoNextest (
            checkArgs
            // {
              cargoArtifacts = checkArtifacts;
              cargoNextestExtraArgs = "--workspace ${excludeServiceTests} --profile ci";
            }
          );

          deny = craneLib.cargoDeny {
            inherit (commonArgs) pname version;
            inherit src;
          };
        };

        devShells.default = pkgs.mkShell {
          name = "keystone-dev";

          nativeBuildInputs = with pkgs; [
            rustToolchain
            pkg-config
            # `crates/storage/build.rs` needs protoc.
            protobuf
            # aws-lc-sys (`aws-lc` / `fips` features) needs cmake, a C
            # compiler and clang.
            cmake
            clang
            gnumake
          ];

          buildInputs = with pkgs; [
            openssl
            zlib
            tpm2-tss
          ];

          packages = with pkgs; [
            # Cargo helpers
            cargo-nextest
            cargo-deny
            cargo-audit
            # Commit/lint tooling (see .pre-commit-config.yaml)
            pre-commit
            committed
            typos
            gitleaks
            # Policy and API tests (`tools/start-api.sh`)
            open-policy-agent
            spire
            curl
            jq
            openssl
            # Docs
            mdbook
          ];

          env = {
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            PROTOC = "${pkgs.protobuf}/bin/protoc";
            # aws-lc-sys bindgen needs libclang.
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          };
        };

        formatter = pkgs.nixfmt;
      }
    );
}
