# Disposable Ubuntu test host with systemd.
#
# A plain ubuntu:24.04 image has no systemd, so `systemd:` tasks and service
# verification cannot run. This image exists only for tests/integration/run.sh.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv python3 python3-yaml python3-apt \
        ansible-core openssh-server sudo \
        ufw fail2ban python3-systemd \
        curl gnupg ca-certificates rsync procps iproute2 \
        nftables iptables auditd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && ssh-keygen -A

# A non-root administrator: the SSH role refuses to disable root login unless a
# /home user has a key, so the image must have somewhere to put one.
# Ubuntu base images already ship an `ubuntu` user; reuse it when present.
RUN if id -u ubuntu >/dev/null 2>&1; then \
        usermod -aG sudo ubuntu; \
    else \
        useradd -m -s /bin/bash -G sudo ubuntu; \
    fi \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
