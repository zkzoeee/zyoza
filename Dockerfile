# Build the gallery server (landing page, Studio, docs). All pages are compiled into the binary.
FROM rust:1.99-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Ragu's x86-64 field assembly needs BMI2 and ADX. There is no runtime CPU detection, so this
# binary only runs on CPUs with both (Fly's machines have them).
ENV RUSTFLAGS="-C target-feature=+adx,+bmi2"
RUN cargo build --release --locked -p zyoza-gallery-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home zyoza
COPY --from=build /src/target/release/zyoza-gallery-demo /usr/local/bin/zyoza-gallery-demo
USER zyoza
ENV ZYOZA_LISTEN=0.0.0.0:8080
EXPOSE 8080
CMD ["zyoza-gallery-demo"]
