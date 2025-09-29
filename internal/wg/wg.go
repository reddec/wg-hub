package wg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Network struct {
	Interface  string        `json:"interface"`
	PrivateKey []byte        `json:"-"` // no need to expose
	PublicKey  []byte        `json:"public_key"`
	ListenPort int           `json:"listen_port"`
	FWMark     string        `json:"fw_mark"`
	Peers      []NetworkPeer `json:"peers"`
}

type NetworkPeer struct {
	Peer
	LatestHandshake time.Time `json:"latest_handshake"`
	TransferRx      int64     `json:"transfer_rx"`
	TransferTx      int64     `json:"transfer_tx"`
}

type Peer struct {
	PublicKey    []byte   `json:"public_key"`
	PresharedKey string   `json:"-"` // do not want to support atm
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"keepalive"` // 0 means no keep alive
}

// SetPeer configures a peer on the given WireGuard network using the provided Peer object and executes the wg command.
func SetPeer(ctx context.Context, network string, peer Peer) error {
	var args = []string{
		"set", network,
		"peer", base64.StdEncoding.EncodeToString(peer.PublicKey),
	}
	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", peer.PresharedKey)
	}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.Keepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.Keepalive))
	}
	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}

	cmd := exec.CommandContext(ctx, "wg", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

// RemovePeer removes a peer from the specified WireGuard network using its public key.
func RemovePeer(ctx context.Context, network string, publicKey []byte) error {
	cmd := exec.CommandContext(ctx, "wg", "set", network,
		"peer", base64.StdEncoding.EncodeToString(publicKey),
		"remove")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

type KeyPair struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

// GenKey generates a new WireGuard key pair using the system's `wg` command-line tool.
// It returns a KeyPair containing the private and public keys or an error if the operation fails.
func GenKey(ctx context.Context) (*KeyPair, error) {
	pkRaw, err := exec.CommandContext(ctx, "wg", "genkey").Output()
	if err != nil {
		return nil, fmt.Errorf("genkey: %w", err)
	}
	pk, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(pkRaw)))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = bytes.NewReader(pkRaw)
	pubRaw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pubkey: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(pubRaw)))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	return &KeyPair{
		PrivateKey: pk,
		PublicKey:  pub,
	}, nil
}

func Get(ctx context.Context, name string) (*Network, error) {
	cmd := exec.CommandContext(ctx, "wg", "show", name, "dump")
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "WG_COLOR_MODE=never")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("capture stdout: %w", err)
	}
	defer pipe.Close()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("run wg: %w", err)
	}

	networks, err := Parse(pipe, name)
	if err != nil {
		return nil, fmt.Errorf("parse networks: %w", err)
	}

	return networks, cmd.Wait()
}

// Parse reads interface and peer information from the provided io.Reader and returns a map of Network structures.
// Each key in the resulting map corresponds to a network interface, and its value contains details about the interface.
// Returns an error if any parsing or decoding issue occurs during the processing of the input.
func Parse(stream io.Reader, interfaceName string) (*Network, error) {
	var network Network
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		switch len(parts) {
		case 4:
			// headline for network
			privateKey, err := base64.StdEncoding.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("decode private key: %w", err)
			}
			publicKey, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("decode public key: %w", err)
			}
			port, err := strconv.Atoi(parts[2])
			if err != nil {
				return nil, fmt.Errorf("parse port: %w", err)
			}
			network = Network{
				Interface:  interfaceName,
				PrivateKey: privateKey,
				PublicKey:  publicKey,
				ListenPort: port,
				FWMark:     parts[3],
			}
		case 8:
			// peer

			publicKey, err := base64.StdEncoding.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("decode public key: %w", err)
			}
			presharedKey := parts[1]
			if presharedKey == "(none)" {
				presharedKey = ""
			}

			ts, err := strconv.ParseInt(parts[4], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse timestamp: %w", err)
			}

			rx, err := strconv.ParseInt(parts[5], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse rx: %w", err)
			}

			tx, err := strconv.ParseInt(parts[6], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse tx: %w", err)
			}

			keepAlive, err := strconv.Atoi(parts[7])
			if err != nil {
				keepAlive = 0 // poor man parsing
			}

			peer := NetworkPeer{
				Peer: Peer{
					PublicKey:    publicKey,
					PresharedKey: presharedKey,
					Endpoint:     parts[2],
					AllowedIPs:   strings.Split(parts[3], ","),
					Keepalive:    keepAlive,
				},
				LatestHandshake: time.Unix(ts, 0),
				TransferRx:      rx,
				TransferTx:      tx,
			}

			network.Peers = append(network.Peers, peer)

		default:
			slog.Debug("skipping unknown line", "line", scanner.Text(), "fields_num", len(parts))
			continue
		}

	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse wg: %w", err)
	}

	return &network, nil
}

// Save saves the provided WireGuard network using the `wg-quick` command.
func Save(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "wg-quick", "save", name)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
