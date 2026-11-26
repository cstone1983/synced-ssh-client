# Releasing

There is one code branch, `main`. Android and Windows build from the same
commit, because they share the core in `packages/`.

## Android

The app builder (cstone1983/app-builder) builds the APK from `main` and
publishes it to the Stone Apps catalog. Nothing to do in this repo.

## Windows

A Windows release is a tag on `main` that starts with `windows-v`:

```
git checkout main
git pull
git tag windows-v0.1.0
git push origin windows-v0.1.0
```

Pushing the tag runs CI. When the tests and the Windows build pass, the
`windows-release` job creates a GitHub release named after the tag with the
installer (`sshsync-setup-<version>.exe`) and its SHA-256
(`sshsync-setup-<version>.exe.sha256`) attached. The app and installer take
their version from the part after `windows-v`, so it must look like `1.2.3`
(optionally `-beta1`). Bump `version:` in `app/pubspec.yaml` to match, so
branch builds show the right number too.

## Windows updates

The Windows app checks GitHub for a newer `windows-v` release when it is
unlocked (once per start; can be turned off in Settings) and from
Settings > Check for updates. It skips pre-releases, downloads the installer,
refuses it unless it matches the published SHA-256, then runs it silently and
quits; the installer upgrades in place and starts the app again.

The checksum catches a broken or swapped download. It does not protect
against someone who controls this GitHub repository, because they could
publish both files; the installer is not code-signed.

A version with a dash, like `windows-v0.2.0-beta1`, is marked as a
pre-release.

If a release build fails, fix it on `main`, delete the tag
(`git push origin :refs/tags/windows-v0.1.0` and `git tag -d windows-v0.1.0`)
and tag again.
