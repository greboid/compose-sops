package volume

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const contentType = "application/vnd.docker.plugins.v1.2+json"

type nameRequest struct {
	Name string
	Opts map[string]string
	ID   string
}

type apiVolume struct {
	Name       string
	Mountpoint string         `json:",omitempty"`
	Status     map[string]any `json:",omitempty"`
}

// Handler serves the Docker volume plugin protocol for d.
func Handler(d *Driver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /Plugin.Activate", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]any{"Implements": []string{"VolumeDriver"}})
	})
	mux.HandleFunc("POST /VolumeDriver.Capabilities", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]any{"Capabilities": map[string]string{"Scope": "local"}})
	})
	handle(mux, "Create", func(r nameRequest) (any, error) {
		return struct{}{}, d.Create(r.Name, r.Opts)
	})
	handle(mux, "Remove", func(r nameRequest) (any, error) {
		return struct{}{}, d.Remove(r.Name)
	})
	handle(mux, "Mount", func(r nameRequest) (any, error) {
		mp, err := d.Mount(r.Name, r.ID)
		return map[string]string{"Mountpoint": mp}, err
	})
	handle(mux, "Unmount", func(r nameRequest) (any, error) {
		return struct{}{}, d.Unmount(r.Name, r.ID)
	})
	handle(mux, "Path", func(r nameRequest) (any, error) {
		mp, err := d.Path(r.Name)
		return map[string]string{"Mountpoint": mp}, err
	})
	handle(mux, "Get", func(r nameRequest) (any, error) {
		v, err := d.Get(r.Name)
		return map[string]apiVolume{"Volume": toAPI(v)}, err
	})
	handle(mux, "List", func(nameRequest) (any, error) {
		vols := d.List()
		out := make([]apiVolume, 0, len(vols))
		for _, v := range vols {
			out = append(out, toAPI(v))
		}
		return map[string][]apiVolume{"Volumes": out}, nil
	})
	return mux
}

func toAPI(v Volume) apiVolume {
	status := map[string]any{"file": v.File}
	if len(v.Keys) > 0 {
		status["keys"] = v.Keys
	}
	return apiVolume{Name: v.Name, Mountpoint: v.Mountpoint, Status: status}
}

func handle(mux *http.ServeMux, op string, fn func(nameRequest) (any, error)) {
	mux.HandleFunc("POST /VolumeDriver."+op, func(w http.ResponseWriter, r *http.Request) {
		var req nameRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil && len(body) > 0 {
			err = json.Unmarshal(body, &req)
		}
		if err != nil {
			fail(w, fmt.Errorf("invalid request: %w", err))
			return
		}
		resp, err := fn(req)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, resp)
	})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", contentType)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"Err": err.Error()})
}

// Serve listens on the unix socket at path until ctx is done.
func Serve(ctx context.Context, path string, h http.Handler) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot remove stale socket: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
