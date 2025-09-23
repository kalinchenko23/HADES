# Dockerfile
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV MSF_RPC_PORT=55552
ENV MSF_PASSWORD=password
ENV PGDATA=/var/lib/postgresql/data

# Install required packages (metasploit + postgres + useful tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      postgresql \
      postgresql-contrib \
      python3 \
      python3-pip \
      ca-certificates \
      net-tools \
      iproute2 \
      procps \
      curl \
      less \
      vim \
      sudo \
      wget \
      findutils \
      gnupg2 && \
    apt-get install -y metasploit-framework || true && \
    pip3 install --no-cache-dir msfrpc pymetasploit3 || true && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*

# Ensure msf bin dir is on PATH (Metasploit often installs under /usr/share/.../bin)
ENV PATH="/usr/share/metasploit-framework/bin:${PATH}"

# Ensure PGDATA exists
RUN mkdir -p ${PGDATA} && chown -R 999:999 ${PGDATA} || true

# copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE ${MSF_RPC_PORT}/tcp

CMD ["/entrypoint.sh"]
