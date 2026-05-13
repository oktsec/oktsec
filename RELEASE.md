# Release process

## Cutting a release

```sh
git pull --ff-only origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag push triggers parallel publish workflows that ship the
multi-arch binaries, the Docker image, and the Python SDK.

## Release authorisation

Release-authorisation steps (credential model, repository protections,
recurring rotation) are kept in the maintainer runbook outside this
repository. Maintainers who need access to that runbook can request
it from the project owner.
