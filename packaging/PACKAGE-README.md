# PHP2Shell Fix CLI distribution image

This early-preview image distributes the Linux amd64 CLI only. It does not contain PHP, a shell, an operating-system package manager or a server. It does not scan the Docker host or other containers. Running it by itself should return `NO_PHP_CLI_FOUND`, not a clean bill of health.

Copy `/usr/local/bin/php2shell-fix` from the published image, preferably pinned by its verified digest, into an existing PHP image in a Docker multi-stage build. Run `php2shell-fix scan --php /actual/path/to/php --json` in that image. Choose the PHP executable that really belongs to that image. Only that CLI is inspected; PHP-FPM, Apache/IIS workers and applications remain outside this validation.

Do not mount the host root filesystem, PHP configuration directories or Docker socket into this image. Do not use privileged mode. No host credentials, private configuration, backups or reports are included.

Container mutation remains unsupported. Use the application's existing image build and deployment procedure for PHP updates and configuration changes. The tool does not install security releases or restart services. Do not treat a version finding as proof of vendor provenance or that a deployed web worker is patched.

Source and MIT license: https://github.com/felixstudio-dev/apply-correction-PHP2Shell
