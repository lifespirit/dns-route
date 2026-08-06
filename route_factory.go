package main

import (
	"context"
	"errors"
	"fmt"
)

var newConfiguredBGPSpeaker = func(ctx context.Context, cfg GoBGPSpeakerConfig) (BGPSpeaker, error) {
	return NewGoBGPSpeaker(ctx, cfg)
}

func buildRouteBackends(ctx context.Context, app *App, cfg *Config) ([]RouteBackend, error) {
	if app == nil {
		return nil, fmt.Errorf("route backend app is nil")
	}
	if cfg == nil {
		return nil, fmt.Errorf("route backend config is nil")
	}
	mode := cfg.RouteMode
	if mode == "" {
		mode = RouteModeKernel
	}

	backends := make([]RouteBackend, 0, 2)
	closeOnError := func(err error) ([]RouteBackend, error) {
		var closeErrs []error
		for _, backend := range backends {
			if backend != nil {
				closeErrs = append(closeErrs, backend.Close())
			}
		}
		return nil, errors.Join(err, errors.Join(closeErrs...))
	}

	if mode.UsesKernel() {
		backends = append(backends, NewKernelRouteBackendForConfig(app, cfg))
	}
	if mode.UsesBGP() {
		speakerCfg, err := cfg.BGP.SpeakerConfig(cfg.RouteIPv4, cfg.RouteIPv6)
		if err != nil {
			return closeOnError(fmt.Errorf("invalid BGP config: %w", err))
		}
		speaker, err := newConfiguredBGPSpeaker(ctx, speakerCfg)
		if err != nil {
			return closeOnError(fmt.Errorf("create BGP speaker: %w", err))
		}
		backend, err := NewBGPRouteBackend(
			speaker,
			cfg.BGP.RequireEstablished,
			cfg.RouteIPv4,
			cfg.RouteIPv6,
		)
		if err != nil {
			_ = speaker.Close()
			return closeOnError(fmt.Errorf("create BGP route backend: %w", err))
		}
		backends = append(backends, backend)
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("route mode %q produced no backends", mode)
	}
	return backends, nil
}

func closeRouteBackends(backends []RouteBackend) error {
	var errs []error
	for _, backend := range backends {
		if backend == nil {
			continue
		}
		if err := backend.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s backend: %w", backend.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func sameRouteBackendConfig(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.RouteMode == b.RouteMode &&
		a.RouteTable == b.RouteTable &&
		a.RouteIPv4 == b.RouteIPv4 &&
		a.RouteIPv6 == b.RouteIPv6 &&
		a.WGInterface == b.WGInterface &&
		a.WGGatewayV4 == b.WGGatewayV4 &&
		a.WGGatewayV6 == b.WGGatewayV6 &&
		a.BGP == b.BGP
}
