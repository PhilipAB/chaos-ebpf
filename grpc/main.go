package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ebpf ./../ebpf/ebpf.c -- -I.

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	nf "github.com/philipab/ebpf-proto/grpc/protos"
	"github.com/philipab/ebpf-proto/grpc/server"
	"github.com/philipab/ebpf-proto/grpc/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "8080"
	}
	log.Printf("Networkfilter server listening on port %s", grpcPort)
	gs := grpc.NewServer()
	nfs := server.NewNetworkfilterServer()
	// Gracefully shutdown container by reacting to SIGTERM
	// https://github.com/GoogleCloudPlatform/golang-samples/blob/main/run/sigterm-handler/main.go
	// Create channel to listen for signals.
	signalChan := make(chan os.Signal, 1)

	// SIGTERM handles Kubernetes Pod termination signal.
	// https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
	signal.Notify(signalChan, syscall.SIGTERM)
	// according to the docs by default all shutdowns are graceful within 30 seconds
	// hence, the following go routine will theoretically prolong the shutdown process to 30 seconds
	go func() {
		// let's listen/react to the SIGTERM signal
		<-signalChan
		// avoid memory leaks ... clean up all resources
		err := nfs.CleanUp()
		if err != nil {
			// to prevent the prolonged termination, exit the program immediately if the cleanup process was successful
			os.Exit(0)
		}
	}()
	nf.RegisterNetworkFilterServer(gs, nfs)
	reflection.Register(gs)

	err := state.InitializeXfsmTable()
	if err != nil {
		log.Printf("failed to initialize pinned ebpf map - xfsm table: %v", err)
	}

	l, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Printf("failed to listen: %v", err)
	}
	if err := gs.Serve(l); err != nil {
		log.Printf("failed to serve: %v", err)
	}
}
