FROM node:22-bookworm

# Install C++ build tools and libpcap
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project
COPY . .

# Install backend dependencies
WORKDIR /app/backend
RUN npm ci

# Build C++ DPI engine
WORKDIR /app/Packet_analyzer-main
RUN rm -rf build \
    && mkdir build \
    && cd build \
    && cmake .. \
    && cmake --build . --config Release

# Build frontend
WORKDIR /app/frontend
RUN npm ci && npm run build

# Backend
WORKDIR /app/backend

ENV NODE_ENV=production

EXPOSE 3001

CMD ["npm", "start"]
