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
installer (`sshsync-setup-<version>.exe`) attached. The installer's version
is the part after `windows-v`.

A version with a dash, like `windows-v0.2.0-beta1`, is marked as a
pre-release.

If a release build fails, fix it on `main`, delete the tag
(`git push origin :refs/tags/windows-v0.1.0` and `git tag -d windows-v0.1.0`)
and tag again.
