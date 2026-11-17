# Changelog

## 0.1.0 (unreleased)

First release.

- `basely advise [DOCKERFILE]` compares each stage's base image with official `-slim`/`-alpine` variants, Docker Hardened Images, Chainguard images and the newest release of the same runtime, for Python, Node.js, Go, Java, Debian, Ubuntu and Alpine.
- `basely advise --image REF` and `basely compare IMAGE...` work without a Dockerfile.
- Reads manifests and package databases (dpkg, distroless `status.d`, apk) straight from the registry, using `docker login` credentials. No image is pulled.
- Looks up every package in OSV under its distro's ecosystem, and classifies each advisory as fixable, unfixed or under investigation, with a CVSS 3.x severity. Distro-ignored, Chainguard false-positive and kernel advisories are left out.
- Checks each candidate's fit with its stage: shell and package manager for `RUN` steps, glibc versus musl, runtime version, user, platforms and age.
- Output: terminal, Markdown for PR comments, JSON with every advisory, and a self-contained offline HTML report.
- `--fail-on fixable,critical,better,root` for CI, and a composite GitHub Action.
