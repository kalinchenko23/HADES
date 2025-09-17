# Dockerfile for a Kali-based image with Metasploit + msfrpcd
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV MSF_RPC_PORT=55552

# Keep layers compact, install metasploit and lightweight tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      metasploit-framework \
      postgresql \
      python3 \
      python3-pip \
      ca-certificates \
      net-tools \
      iproute2 \
      procps \
      curl \
      less \
      vim && \
    pip3 install --no-cache-dir msfrpc pymetasploit3 || true && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*

# copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 55552/tcp

# default environment password (override with -e MSF_PASSWORD=...)
ENV MSF_PASSWORD=password

CMD ["/entrypoint.sh"]
