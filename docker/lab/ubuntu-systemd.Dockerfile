FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    aide \
    apache2 \
    auditd \
    ca-certificates \
    cron \
    curl \
    dbus \
    fail2ban \
    iproute2 \
    iptables \
    libcap2-bin \
    libpam-pwquality \
    openssl \
    openssh-server \
    postgresql \
    postgresql-contrib \
    rsync \
    sudo \
    systemd \
    systemd-sysv \
    tmux \
    ufw \
    wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /vagrant/logs /opt/ncae

COPY docker/lab/container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod +x /usr/local/bin/container-entrypoint.sh

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/bin/container-entrypoint.sh"]
CMD ["/sbin/init"]
