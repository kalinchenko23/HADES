# Build a Kali image with Metasploit and msfrpcd available.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV MSF_RPC_PASS=password
ENV MSF_RPC_PORT=55552

RUN echo "deb http://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware" > /etc/apt/sources.list

# install packages (metasploit, supervisor, postgresql, msfrpcd is part of metasploit)
RUN apt-get clean && rm -rf /var/lib/apt/lists/* \
 && apt-get update -o Acquire::CompressionTypes::Order::=gz \
 && apt-get -o Acquire::http::No-Cache=True -o Acquire::BrokenProxy=true install -y --no-install-recommends \
    metasploit-framework \
    postgresql \
    supervisor \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
 && rm -rf /var/lib/apt/lists/*
# Ensure msfdb utility available and init DB
RUN msfdb init || true

# Supervisor config directory
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 55552

CMD ["/usr/local/bin/entrypoint.sh"]