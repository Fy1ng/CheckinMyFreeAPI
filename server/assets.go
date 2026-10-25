// Package frontend embeds the shared WebUI in the standalone Go executable.
package frontend

import "embed"

//go:embed static/*
var Files embed.FS
