FROM python:3.11-slim AS python-runtime

# Minimal base with security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /sbin/nologin sandbox

# Copy execution entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Security settings
RUN chmod 1777 /tmp

WORKDIR /tmp/sandbox
USER sandbox

ENTRYPOINT ["/entrypoint.sh"]
