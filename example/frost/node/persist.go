package node

import (
	"fmt"
	"os"

	"github.com/seabond/go-mpc/frost"
)

// SaveKeyShare encrypts and writes the node's KeyShare to path.
func (n *Node) SaveKeyShare(path string, enc frost.SetupEncryptor) error {
	ct, err := frost.MarshalEncrypted(n.State.KeyShare, enc)
	if err != nil {
		return fmt.Errorf("node %d SaveKeyShare: %w", n.ID, err)
	}
	if err := os.WriteFile(path, ct, 0600); err != nil {
		return fmt.Errorf("node %d SaveKeyShare: write: %w", n.ID, err)
	}
	return nil
}

// LoadKeyShare reads an encrypted KeyShare from path and restores the node's state.
func (n *Node) LoadKeyShare(path string, enc frost.SetupEncryptor) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("node %d LoadKeyShare: read: %w", n.ID, err)
	}
	ks, err := frost.UnmarshalEncrypted(blob, enc)
	if err != nil {
		return fmt.Errorf("node %d LoadKeyShare: %w", n.ID, err)
	}
	n.State = frost.NewSignerState(ks)
	n.ID = ks.ID
	n.AllIDs = ks.AllIDs
	n.Threshold = ks.Threshold
	return nil
}

// NewFromFile creates a Node by loading an encrypted KeyShare from disk.
func NewFromFile(path string, enc frost.SetupEncryptor) (*Node, error) {
	n := &Node{}
	if err := n.LoadKeyShare(path, enc); err != nil {
		return nil, err
	}
	return n, nil
}
