FROM debian:bookworm-slim

# Prevent interactive installer prompts
ENV DEBIAN_FRONTEND=noninteractive

# Build Omni-Runtime Environment (Node 20, Python 3.11+, Go 1.21+)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    python3 \
    golang \
    build-essential \
    ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root 'sandbox' user with restricted permissions
# The backend runs as root to maintain supervisor control, but executes AI code strictly under this UID.
RUN useradd -m -s /bin/bash sandbox && \
    mkdir -p /app && \
    chown -R root:root /app

WORKDIR /app

# Copy application and build
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Make the secure sandbox directory and ensure everyone can write but only owners can delete (sticky bit + 777)
RUN mkdir -p /tmp/secureai-sandbox && chmod 1777 /tmp/secureai-sandbox

EXPOSE 3000

ENV NODE_ENV=production

CMD ["npm", "start"]
