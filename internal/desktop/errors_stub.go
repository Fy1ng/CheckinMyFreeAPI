//go:build !desktop || (!windows && !linux)

package desktop

func reportStartupError(string) {}
