# build context: repository root. Runs the simulation fallback; use `attach` on a Linux host with CAP_BPF.
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml ./
COPY reconstructor reconstructor
COPY probe/common probe/common
COPY probe/userspace probe/userspace
RUN cargo build --release -p shadowapi-probe

FROM debian:bookworm-slim
COPY --from=build /src/target/release/shadowapi-probe /usr/local/bin/shadowapi-probe
COPY probe/sample-traffic.ndjson /sample-traffic.ndjson
ENTRYPOINT ["shadowapi-probe"]
CMD ["simulate", "/sample-traffic.ndjson"]
