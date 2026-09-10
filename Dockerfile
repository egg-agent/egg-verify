FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./
# Public deploy config: Base mainnet USDC via the Dexter facilitator.
ENV PORT=7860 \
    X402_NETWORK=eip155:8453 \
    X402_FACILITATOR_URL=https://x402.dexter.cash \
    X402_PAY_TO=0x146ECb985fc03640F44aD0c8d9aB16eb233d1A83
EXPOSE 7860
CMD ["node", "server.js"]
