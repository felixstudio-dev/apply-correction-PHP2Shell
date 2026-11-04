# Linux amd64 OCI distribution package

This package distributes the statically linked PHP2Shell Fix CLI for use in an existing PHP image. It contains no PHP runtime, shell, package manager or host access. The application's container-mutation limitations remain unchanged.

The initial package is version `v0.1.0-alpha.1`, built from application revision `7a0600ecd84bc32c817d9cb55d6d59976d2331e9`. Packaging changes do not move the existing release tag. Only Linux amd64 is built and tested; there is no `latest` tag.

## Build and publication

The **OCI package** workflow tests packaging on pull requests with read-only repository access. Its manual run defaults to build/test only. A maintainer may select `publish=true` from `main` to publish after all checks pass. Only the publication job receives `packages: write` through the temporary `GITHUB_TOKEN`; no personal access token or repository-write permission is required. The login uses an isolated temporary Docker configuration removed at job completion.

Publication refuses an existing version tag rather than replacing it. Before retrying a failed run, inspect the registry: a push may have succeeded even if a later verification failed. A new package is private by default. Verify its visibility and repository association before claiming it can be pulled anonymously; public visibility requires an authorized package-settings change.

The workflow checks unit tests, `go vet`, static ELF architecture, the image file allowlist, non-root read-only execution without network, a real PHP 8.4.27 CLI fixture pinned by digest, and binary integrity before and after registry publication. These checks do not validate PHP-FPM/web workers, production INIs, container mitigation or PHP upgrades. The build receipt records the source, compiler, fixture digest and binary hash.

## Use the published package

The [public GitHub Packages entry](https://github.com/felixstudio-dev/apply-correction-PHP2Shell/pkgs/container/apply-correction-php2shell) provides `ghcr.io/felixstudio-dev/apply-correction-php2shell:v0.1.0-alpha.1` for Linux amd64. Publication and anonymous registry access were verified on November 4, 2026, following the [successful publication workflow](https://github.com/felixstudio-dev/apply-correction-PHP2Shell/actions/runs/41781267106). Pin the published immutable digest in a downstream Dockerfile:

```dockerfile
FROM ghcr.io/felixstudio-dev/apply-correction-php2shell@sha256:2dbfe81fc6762b19b653c0cf806f97343dcb7e6f467ce2328ea51feabed468dd AS php2shell
FROM your-existing-php-image
COPY --from=php2shell /usr/local/bin/php2shell-fix /usr/local/bin/php2shell-fix
```

Run `php2shell-fix scan --php /actual/path/to/php --json` inside the resulting image. Only the selected PHP CLI is inspected. The distribution image by itself returns `NO_PHP_CLI_FOUND`; this is not evidence of a protected system.

Do not grant privileged mode or mount the Docker socket, host root filesystem, PHP configuration or backup directories into this distribution image. Use your existing build/deployment procedure for PHP updates and configuration changes. The image includes the project MIT license and notices for its Go runtime and pinned `golang.org/x/sys` dependency.
