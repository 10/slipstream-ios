# Publishing Slipstream

Source and packages live in `10/slipstream-ios`. The Sileo source, **https://10.github.io/slipstream-ios/**, is a signed flat APT repository that the release workflow deploys to GitHub Pages. Only generated repository files are deployed; source, captures, proxy lists and credentials are not.

## Release a build

1. Merge the changes to `main`.
2. Start **Actions → Release Slipstream → Run workflow** on `main` with a new `MAJOR.MINOR.PATCH` version, or:

```sh
gh workflow run release.yml --repo 10/slipstream-ios --ref main -f version=0.7.2
gh run watch --repo 10/slipstream-ios
```

3. When the run passes, Sileo users refresh their sources and install the update.

There is no release on an ordinary push. The workflow builds with Xcode 26.6 and Rust 1.96.1, runs the host tests, builds and checks both the rootless and rootful `.deb`, signs the APT indexes, stages a draft GitHub release, deploys Pages, then publishes the release. It rejects non-main branches and versions at or below an existing published release. App and Debian versions come from the requested version; `VERSION` is the default for local builds.

The index lists every published version for both architectures: the workflow downloads earlier `.deb` files from GitHub Releases before signing, so a cached Sileo index never points at a missing file and older versions remain installable. A failed Pages deployment leaves a draft release; rerun the workflow on the same commit to finish. A published version is never overwritten: choose a newer version for a fix.

## Signing

The repository public key is checked in as `packaging/repository-key.gpg`. The private key is stored in the **APT_SIGNING_KEY** Actions secret, imported only into the temporary runner keyring and deleted after the job. A recovery copy exists only in the development Mac's ignored `.local/signing` directory. Never commit or publish that directory or the secret.

`Release.gpg` and `InRelease` sign the package indexes; each index carries the packages' SHA-256 and SHA-512 checksums. The workflow signs with the exact checked-in key fingerprint, so an unrelated secret key cannot silently replace it.

The package installs the public key for authenticated APT refreshes. Sileo can add the HTTPS source directly. For command-line APT on a new phone, first install the key from the Pages site at `/var/jb/etc/apt/trusted.gpg.d/slipstream.gpg` (rootful: `/etc/apt/trusted.gpg.d/slipstream.gpg`) and verify its fingerprint against the checked-in key. Do not disable signature verification globally. Removing the package removes its key too.

## Package lifecycle

Package ID: `io.github.10.slipstream`; architecture: `iphoneos-arm64` (rootless) or `iphoneos-arm` (rootful, built with `SLIPSTREAM_SCHEME=rootful`); iOS minimum: 14.0; requires `uikittools` 2.1.2 or newer, because older `uicache` registers the app proxy provider without its entitlements. The app's bundle ID, `local.slipstream.app`, is unchanged from earlier releases.

- A clean installation starts with protection off until a proxy is configured.
- Saved lists, proxy selection and app settings survive upgrades. Upgrades keep the VPN configuration and saved enabled preference, and reconnect the updated provider. The package refuses to upgrade a release before 0.7.0: remove it first, or install 0.7.1 before the newer version.
- Removal disables the engine and restores networking before files are removed. Saved settings remain for reinstall; `apt-get purge io.github.10.slipstream` removes them too.
- To install an earlier release, turn protection off first, then select the proxy again in the app. Releases before 0.7.2 refuse to replace this version while protected.
- `slipstreamctl uninstall` runs `apt-get remove`.

A locally installed `.deb` is managed by Sileo like any other package. Once the phone has the source, newer versions from the repository replace it as ordinary updates.

## Local packaging

```sh
SLIPSTREAM_VERSION=0.7.2 ./scripts/build.sh
python3 scripts/release.py package 0.7.2
python3 tests/check_package.py build/io.github.10.slipstream_0.7.2_iphoneos-arm64.deb
```

`release.py package` follows the last build's scheme. To test a signed repository locally, point `GNUPGHOME` at a keyring holding the signing key:

```sh
python3 scripts/release.py repository /tmp/repo build/io.github.10.slipstream_*.deb --signing-key FINGERPRINT
```

Build tools are Xcode, Rust, GitHub CLI, `ldid`, `dpkg`, Python 3, and GnuPG for signing. Packages use xz compression and root:wheel ownership; only the app's fixed-purpose helper is setuid.

`release.py` writes Slipstream's MIT license followed by notices for the active iOS dependency graph into the package's `copyright` file, and stops on unreviewed licenses or missing license text. License supplements are pinned under `packaging/licenses`.

## Repository setup

GitHub Pages uses **GitHub Actions** as its source, and the `github-pages` environment accepts deployments from `main`. To move the source to a custom domain, configure it in Pages and DNS, update `REPO` in `scripts/release.py` and publish a new release. Existing users then update their Sileo source.
