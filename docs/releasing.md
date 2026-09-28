# Releasing bootintel-cli

The release workflow is `workflow_dispatch` only. Nothing ships on a push, and
no tag is created automatically, so a stray tag can never publish a build.

## One-time setup

### crates.io token

`cargo install bootintel-cli` needs the crates published, and publishing needs
a registry token. It is NOT in the repository and cannot be, so it lives as a
GitHub Actions secret.

1. Go to <https://crates.io/settings/tokens> and create a token.
   Scopes: `publish-new` and `publish-update`. Nothing else.
   Name it something traceable, for example `github-actions-bootintel-cli`.
2. In this repository, go to
   **Settings > Secrets and variables > Actions > New repository secret**.
3. Name it exactly `CARGO_REGISTRY_TOKEN`. Paste the token as the value.

That name is what `.github/workflows/cli-release.yml` reads. Until the secret
exists, the `publish-crates` job fails immediately with a message pointing
here, rather than part-publishing and leaving a version that can never be
reused. crates.io versions are permanent: a wrong publish cannot be deleted,
only yanked.

The token is never echoed by the workflow and is only passed as an environment
variable to the two `cargo publish` steps.

### Homebrew tap

`brew install bootintel` needs a public `BootIntel/homebrew-tap` repository.
The formula template is already written at `packaging/homebrew/bootintel.rb`.
Until that repository exists, do not advertise the brew line anywhere: an
install command that fails reads as an abandoned project, which is worse than
having no brew line at all.

## Cutting a release

1. Bump `version` in the workspace `Cargo.toml` **and the `bootintel-detectors`
   version in `crates/cli/Cargo.toml`**, which is pinned exactly because the
   published binary crate has to name a version that exists on the index. Then
   run `cargo update -w` so the lockfile follows, and promote the
   `[Unreleased]` changelog section. Forgetting the second bump fails
   `cargo update -w` immediately with "required by package bootintel", so it
   cannot reach a release, but it is the step that gets missed.
   Versioning policy is documented at the top of `CHANGELOG.md`. The crate is
   pre-1.0, so the leading zero is the major component: a breaking change
   moves the minor, not the major.
2. Merge that through a pull request with CI green.
3. Dispatch `cli-release` from `main` with the version, no leading `v`.
   Leave `publish_crates` off for a first pass if you want to inspect the
   binaries before anything reaches crates.io.
4. The workflow builds five targets, attaches `SHA256SUMS`, attests build
   provenance, and creates a **draft** release.
5. Verify before publishing the draft. At minimum, download one archive and
   check it against the published checksum, then run the binary:

   ```sh
   gh release download cli-v<version> --pattern '*x86_64-linux.tar.gz' --pattern SHA256SUMS
   grep x86_64-linux SHA256SUMS | sha256sum -c -
   tar xzf bootintel-v<version>-x86_64-linux.tar.gz && ./bootintel --version
   ```

   Checking the checksum matters more than it looks: it proves the artifact and
   the checksum came from the same build, which is the whole point of shipping
   both.
6. Publish the draft and mark it latest. That creates the tag on the released
   commit.

## Yanking a published version

A crates.io version can be yanked, which stops new dependency resolution and
new installs reaching it, and can be restored with unyank. It can never be
reused: the number is spent whatever happens.

The registry token lives only as a repository secret, which is correct for a
publish credential, so a yank cannot be run from a laptop that does not hold
its own token. Dispatch the `crates-yank` workflow instead. It takes the crate,
the exact version, yank or unyank, and a reason for the run log. It has no
defaults, so it cannot fire by accident, and it refuses a version that is not
on the registry so a typo fails before it reaches crates.io.

## Publishing to crates.io

Order is not optional. `bootintel` declares `bootintel-detectors` with
both a path and a version, so the library must be on the index before the
binary crate can be packaged. `cargo package -p bootintel` fails with
`no matching package named bootintel-detectors` otherwise.

The `publish-crates` job does this in order, waits for the index to become
consistent, and then publishes the binary crate. Dispatch the workflow with
`publish_crates` checked, or run it by hand:

```sh
cargo publish -p bootintel-detectors
# wait for the index
cargo publish -p bootintel
```

The README's Install section offers `cargo install bootintel` as of 0.4.2,
the first release published under that name. Keep the caveat that it builds
from source: the install one-liner is faster for anyone who just wants the
binary.

The crate was `bootintel-cli` for exactly one release, 0.4.1, which has been
yanked. crates.io cannot rename a crate, so the move was to publish under
the new name and yank the old. The old name stays reserved under this
account either way, so nobody else can claim it.
