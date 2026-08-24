FROM node:22-bookworm

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

WORKDIR /app/backend
RUN npm ci

WORKDIR /app/Packet_analyzer-main
RUN rm -rf build \
    && mkdir build \
    && cd build \
    && cmake .. \
    && cmake --build . --config Release

WORKDIR /app/frontend
RUN npm ci && npm run build

WORKDIR /app/backend

ENV NODE_ENV=production

EXPOSE 3001

CMD ["npm", "start"]
