FROM node:22-bookworm-slim

ARG NEXT_VERSION=16.4.0

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

COPY package.json ./
RUN npm pkg set dependencies.next="${NEXT_VERSION}" \
 && npm install --legacy-peer-deps --no-audit --no-fund

COPY . ./
# 16.4.0 is intentionally vulnerable. It may print a security advisory and
# exit once; the retry continues the build.
RUN npx next build || npx next build
RUN chown -R node:node /app

USER node
ENV NODE_ENV=production
EXPOSE 3100
CMD ["npx", "next", "start", "-p", "3100"]
