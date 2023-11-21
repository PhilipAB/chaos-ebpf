package nsswitcher

import (
	"fmt"
	"log"

	"github.com/vishvananda/netns"
)

type NamespaceSwitcher struct {
	originalNs netns.NsHandle
	newNs      netns.NsHandle
}

func (n *NamespaceSwitcher) Close() error {
	err := netns.Set(n.originalNs)
	if err != nil {
		log.Printf("failed switching back to the container's network namespace: %v", err)
	}
	n.originalNs.Close()
	n.newNs.Close()
	return nil
}

func SwitchToHostNamespace() (*NamespaceSwitcher, error) {
	// Retrieving the current container network namespace
	containerNs, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the current network namespace: %v", err)
	}
	// Retrieving the host's network namespace from the mounted path
	hostNs, err := netns.GetFromPath("/host/ns/net")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the host's network namespace: %v", err)
	}

	err = netns.Set(hostNs)
	if err != nil {
		containerNs.Close()
		hostNs.Close()
		return nil, fmt.Errorf("failed switching to the host's network namespace: %v", err)
	}

	return &NamespaceSwitcher{
		originalNs: containerNs,
		newNs:      hostNs,
	}, nil
}

func SwitchToNamedNamespace(name string) (*NamespaceSwitcher, error) {
	// Retrieving the current container network namespace
	containerNs, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the current network namespace: %v", err)
	}
	// Retrieving the host's network namespace from the mounted path
	namedNs, err := netns.GetFromName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve the network namespace %s: %v", name, err)
	}

	err = netns.Set(namedNs)
	if err != nil {
		containerNs.Close()
		namedNs.Close()
		return nil, fmt.Errorf("failed switching to the host's network namespace: %v", err)
	}

	return &NamespaceSwitcher{
		originalNs: containerNs,
		newNs:      namedNs,
	}, nil
}
