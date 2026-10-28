# PHP2Shell in Docker and Managed Hosting

Container images and managed environments are **detection-only or unsupported** for mutation in this release. Do not run a host-level installer against a container volume or bypass a provider's update system.

For containers: identify the image digest and web-serving PHP SAPI, review the base image's vendor security bulletin, rebuild from a patched supported image, validate extensions and application tests, deploy through the existing pipeline, and confirm the running container digest and PHP worker version. Scanning the host's CLI does not assess all container images.

For Plesk, cPanel or shared hosting: use the provider's security update procedure and service ownership model. Plesk publishes its own version/build matrix, including supported rebuilt packages for older branches. An upstream PHP version comparison alone is insufficient.

References: [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [Plesk PHP2Shell vendor notice](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk).
