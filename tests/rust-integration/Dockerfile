FROM agentdns-validation:local
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends postfix && rm -rf /var/lib/apt/lists/*
