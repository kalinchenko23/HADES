FROM kalilinux/kali-rolling:latest

# Overwrite sources.list to ensure we use the main repository
RUN echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list

# Install Metasploit Framework and dependencies
RUN apt-get update && \
    apt-get install -y --fix-missing metasploit-framework && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Expose the msfrpcd port
EXPOSE 55552

# Set default password for msfrpcd
ENV MSFRPC_PASSWORD=password

# Run msfrpcd daemon (SSL disabled, port 55552, username msf)
CMD msfrpcd -S -U msf -P $MSFRPC_PASSWORD -a 0.0.0.0 -p 55552 -f