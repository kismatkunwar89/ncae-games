FROM rockylinux:9

ENV container=docker
ENV LANG=C.UTF-8

RUN dnf -y install epel-release && \
    dnf -y install \
        audit \
        bind \
        bind-utils \
        cronie \
        dbus \
        fail2ban \
        firewalld \
        hostname \
        iproute \
        iptables \
        libcap \
        openssh-server \
        passwd \
        policycoreutils-python-utils \
        procps-ng \
        quota \
        samba \
        samba-client \
        samba-common \
        shadow-utils \
        sudo \
        systemd \
        tmux \
        which && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN mkdir -p /run/sshd /vagrant/logs /opt/ncae

COPY docker/lab/container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod +x /usr/local/bin/container-entrypoint.sh

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/bin/container-entrypoint.sh"]
CMD ["/sbin/init"]
