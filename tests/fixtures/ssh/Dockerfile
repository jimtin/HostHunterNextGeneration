# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG UBUNTU_IMAGE="ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
FROM ${UBUNTU_IMAGE}

ARG TARGETARCH
ARG POWERSHELL_VERSION="7.6.5"
ARG POWERSHELL_AMD64_SHA256="dd683d29a5c95ed43e426f4fe1679469d8b89e78ea955455f6238a0b0e6f1a24"
ARG POWERSHELL_ARM64_SHA256="df09c222871de1f63a65308d50dd717b5e9ff01a1df1b9a5ead0953a56020dbd"
ARG OPENSSH_SERVER_VERSION="1:9.6p1-3ubuntu13.18"
ARG CA_CERTIFICATES_VERSION="20260601~24.04.1"
ARG CURL_VERSION="8.5.0-2ubuntu10.13"

ENV DEBIAN_FRONTEND="noninteractive"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
        "ca-certificates=${CA_CERTIFICATES_VERSION}" \
        "curl=${CURL_VERSION}" \
        "openssh-server=${OPENSSH_SERVER_VERSION}"; \
    case "${TARGETARCH}" in \
        amd64) \
            package_arch="amd64"; \
            package_sha256="${POWERSHELL_AMD64_SHA256}" \
            ;; \
        arm64) \
            package_arch="arm64"; \
            package_sha256="${POWERSHELL_ARM64_SHA256}" \
            ;; \
        *) \
            echo "Unsupported fixture architecture: ${TARGETARCH}" >&2; \
            exit 64 \
            ;; \
    esac; \
    package_name="powershell_${POWERSHELL_VERSION}-1.deb_${package_arch}.deb"; \
    curl \
        --fail \
        --location \
        --proto '=https' \
        --retry 3 \
        --show-error \
        --silent \
        --tlsv1.2 \
        "https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/${package_name}" \
        --output /tmp/powershell.deb; \
    printf '%s  %s\n' "${package_sha256}" /tmp/powershell.deb | sha256sum --check --strict; \
    apt-get install --yes --no-install-recommends /tmp/powershell.deb; \
    test "$(pwsh -NoLogo -NoProfile -Command "\$PSVersionTable.PSVersion.ToString()")" = "${POWERSHELL_VERSION}"; \
    groupadd --gid 10001 hhfixture; \
    groupadd --gid 10002 hhfixture-secret; \
    useradd \
        --create-home \
        --gid 10001 \
        --home-dir /home/hhfixture \
        --shell /bin/bash \
        --uid 10001 \
        hhfixture; \
    passwd --lock hhfixture; \
    install --directory --mode 0700 --owner hhfixture --group hhfixture /home/hhfixture/.ssh; \
    install --mode 0600 --owner hhfixture --group hhfixture /dev/null /home/hhfixture/.ssh/authorized_keys; \
    install --directory --mode 0755 /run/sshd; \
    find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' -delete; \
    rm --force /tmp/powershell.deb; \
    rm --recursive --force /var/lib/apt/lists/*

COPY --chmod=0644 sshd_config /etc/ssh/sshd_config
COPY --chmod=0755 entrypoint.sh /usr/local/bin/hh-ssh-entrypoint
COPY --chmod=0755 healthcheck.sh /usr/local/bin/hh-ssh-healthcheck
COPY --chmod=0755 fixture-askpass.sh /usr/local/bin/hh-ssh-fixture-askpass
COPY --chmod=0755 reset-authorized-keys.sh /usr/local/bin/hh-ssh-reset-authorized-keys
COPY --chmod=0755 rotate-host-key.sh /usr/local/bin/hh-ssh-rotate-host-key

LABEL org.opencontainers.image.title="HostHunter disposable PowerShell SSH fixture" \
      org.opencontainers.image.version="7.6.5" \
      org.opencontainers.image.source="https://github.com/jimtin/HostHunterNextGeneration"

EXPOSE 22

VOLUME ["/run/hosthunter-ssh"]

HEALTHCHECK --interval=2s --timeout=3s --start-period=10s --retries=15 \
    CMD ["/usr/local/bin/hh-ssh-healthcheck"]

ENTRYPOINT ["/usr/local/bin/hh-ssh-entrypoint"]
