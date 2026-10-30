# Contributing to Doppel

Thanks for helping improve Doppel. Changes should preserve the separation and
update-safety guarantees documented in the [threat model](docs/THREAT-MODEL.md).

## Development setup

Doppel is a macOS application and requires macOS 14 or newer, Xcode (including
XCTest), Swift Package Manager, and the Xcode command-line tools.

```sh
git clone https://github.com/aarav-sahni/DoppleGanger.git
cd DoppleGanger
swift package --package-path app resolve
just test
```

Use `just build` to build a local ad-hoc app into `app/.build/app` without
overwriting the installed copy. `just qa` runs the end-to-end checks that need
macOS services and a locally installed ChatGPT app.

## Making changes

- Keep changes focused and explain user-visible behavior in the pull request.
- Add or update tests for behavior that can be tested without a running app.
- Run `just test` and the relevant QA command before opening a pull request.
- Do not commit credentials, signing keys, app bundles, Sparkle artifacts, or
  personal ChatGPT data.
- Do not redistribute a clone of the ChatGPT application. Doppel builds clones
  locally from the user's own installation.

## Releases

Release preparation is documented in the [release notes guide](release-notes/README.md).
The repository's release workflow creates a universal macOS archive and signed
Sparkle appcast; publication to GitHub remains a deliberate, reviewable step.

## Reporting security issues

Please do not open a public issue with an exploit or private data. Contact the
repository owner privately with reproduction steps and the affected commit.
The [threat model](docs/THREAT-MODEL.md) describes the security boundary and
known limitations.
