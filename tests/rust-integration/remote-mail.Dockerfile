# Independent stock client; NET_ADMIN is requested only on its disposable
# container to install the explicitly documented test connection route.
FROM agentdns-mail-validation:local
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
