# Stage 1: Introduce builder stage for installation of dependencies + compilation to eBPF Byte Programs
# Use an ARM golang base image // distribution is not relevant but may impact how to install
# llvm, clanq the required headers etc.
FROM arm64v8/golang:1.21.0-bullseye as builder

# Install llvm, clang, and required headers
RUN apt-get update && apt-get install -y clang llvm libbpf-dev && mkdir /usr/include/asm && \
    for file in /usr/include/aarch64-linux-gnu/asm/*; do \
        ln -s "$file" "/usr/include/asm/$(basename $file)"; \
    done

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Run the go generate commands
RUN go generate ./ebpf/bitflip
RUN go generate ./ebpf/bwmanager
RUN go generate ./ebpf/delay
RUN go generate ./ebpf/duplication
RUN go generate ./ebpf/tshaper

# Build Go application
RUN CGO_ENABLED=0 GOARCH=arm64 go build -o trafficshaper ./grpc/

# Stage 2: Use a "clean" new image, to reduce build size
FROM debian:bullseye-slim

WORKDIR /app

# Copy the built application from the previous stage
COPY --from=builder /app/trafficshaper /app/

CMD [ "./trafficshaper" ]
