//go:build desktop && !desktoptest && (windows || linux)

package desktop

// Released applications never enable a remote-debugging port through environment.
func testBrowserArgs() []string { return nil }
