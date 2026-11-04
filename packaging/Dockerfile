# Distribution image for the statically linked Linux amd64 CLI.
# Build only from the small allowlisted staging context described in README.md.
FROM scratch
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="PHP2Shell Fix CLI distribution" \
      org.opencontainers.image.description="Early-preview Linux amd64 CLI distribution. No PHP runtime or host access is included. Copy the binary into an existing PHP image for read-only CLI assessment; this does not validate web workers or patch PHP." \
      org.opencontainers.image.source="https://github.com/felixstudio-dev/apply-correction-PHP2Shell" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --chmod=0555 php2shell-fix /usr/local/bin/php2shell-fix
COPY --chmod=0444 LICENSE /usr/share/licenses/php2shell-fix/LICENSE
COPY --chmod=0444 THIRD-PARTY-NOTICES.txt /usr/share/licenses/php2shell-fix/THIRD-PARTY-NOTICES.txt
COPY --chmod=0444 PACKAGE-README.md /usr/share/doc/php2shell-fix/README.md
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/php2shell-fix"]
CMD ["scan", "--json"]
