FROM ubuntu:jammy
RUN apt-get update
RUN apt-get install -y clang llvm libbpf-dev libelf-dev libpcap-dev build-essential make 
RUN apt-get install -y linux-tools-common

# Install dependencies
RUN apt-get install -y curl git wget

# Set up Go version and architecture dynamically based on the target architecture
ARG GO_VERSION=1.23.1
ARG TARGETARCH

# Download and install Go based on the target architecture
RUN case "$TARGETARCH" in \
    "amd64") GO_ARCH="amd64" ;; \
    "arm64") GO_ARCH="arm64" ;; \
    "arm") GO_ARCH="armv6l" ;; \
    *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    wget https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
