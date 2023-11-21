# Use an ARM golang base image
FROM arm64v8/golang:1.21.0-bullseye

# Install llvm, clang, and required headers
RUN apt-get update && apt-get install -y clang llvm libbpf-dev && mkdir /usr/include/asm && \
    for file in /usr/include/aarch64-linux-gnu/asm/*; do \
        ln -s "$file" "/usr/include/asm/$(basename $file)"; \
    done

# Set up Go environment
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

# Build your Go application
RUN go build -o trafficshaper ./grpc/

# Set up the command to run your application
CMD [ "./trafficshaper" ]