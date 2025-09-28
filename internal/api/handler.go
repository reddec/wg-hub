package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	"wg-hub/internal/wg"
)

type PeerConfig struct {
	AllowedIPs []string `json:"allowed_ips"`         // required at least one
	Endpoint   string   `json:"endpoint,omitempty"`  // optional
	Keepalive  int      `json:"keepalive,omitempty"` // optional, keepalive in seconds
}

type NewPeer struct {
	PeerConfig
	Keys *wg.KeyPair `json:"keys,omitempty"` // optional, if not set - will be generated
}

func New(interfaceName string, ephemeral bool) http.Handler {
	srv := handlerImpl{
		interfaceName: interfaceName,
		ephemeral:     ephemeral,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", srv.network)
	mux.HandleFunc("POST /peers", srv.createPeer)
	mux.HandleFunc("POST /peers/{peer}", srv.updatePeer)
	mux.HandleFunc("DELETE /peers/{peer}", srv.removePeer)

	return mux
}

type handlerImpl struct {
	interfaceName string
	ephemeral     bool
}

// createPeer handles the creation of a new peer for a WireGuard server based on the provided HTTP request.
// It validates input, generates a key pair, configures the peer, saves the configuration, and returns peer details.
func (srv *handlerImpl) createPeer(w http.ResponseWriter, r *http.Request) {
	var draft NewPeer
	if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
		slog.Error("failed to decode draft", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(draft.AllowedIPs) == 0 {
		slog.Error("failed to draft draft: no allowed ips defined")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if draft.Keys == nil {
		keyPair, err := wg.GenKey(r.Context())
		if err != nil {
			slog.Error("failed to generate key", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		draft.Keys = keyPair
	}

	err := wg.SetPeer(r.Context(), srv.interfaceName, wg.Peer{
		PublicKey:  draft.Keys.PublicKey,
		Endpoint:   draft.Endpoint,
		AllowedIPs: draft.AllowedIPs,
		Keepalive:  draft.Keepalive,
	})
	if err != nil {
		slog.Error("failed to set peer", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := srv.save(r.Context()); err != nil {
		slog.Error("failed save config", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(draft); err != nil {
		slog.Error("failed to encode new peer", "error", err)
		return
	}
}

func (srv *handlerImpl) updatePeer(w http.ResponseWriter, r *http.Request) {
	publicKey, err := base64.StdEncoding.DecodeString(r.PathValue("peer"))
	if err != nil {
		slog.Error("failed to decode peer public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var config PeerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		slog.Error("failed to decode config", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(config.AllowedIPs) == 0 {
		slog.Error("failed to parse config: no allowed ips defined")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = wg.SetPeer(r.Context(), srv.interfaceName, wg.Peer{
		PublicKey:  publicKey,
		Endpoint:   config.Endpoint,
		AllowedIPs: config.AllowedIPs,
		Keepalive:  config.Keepalive,
	})
	if err != nil {
		slog.Error("failed to set peer", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := srv.save(r.Context()); err != nil {
		slog.Error("failed save config", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (srv *handlerImpl) removePeer(w http.ResponseWriter, r *http.Request) {
	publicKey, err := base64.StdEncoding.DecodeString(r.PathValue("peer"))
	if err != nil {
		slog.Error("failed to decode peer public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := wg.RemovePeer(r.Context(), srv.interfaceName, publicKey); err != nil {
		slog.Error("failed to remove peer", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := srv.save(r.Context()); err != nil {
		slog.Error("failed save config", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (srv *handlerImpl) network(w http.ResponseWriter, r *http.Request) {
	info, err := wg.Get(r.Context(), srv.interfaceName)
	if err != nil {
		slog.Error("failed get info from wireguard", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.Error("failed encode info to json", "error", err)
		return
	}
}

func (srv *handlerImpl) save(ctx context.Context) error {
	if srv.ephemeral {
		return nil
	}
	return wg.Save(ctx, srv.interfaceName)
}
