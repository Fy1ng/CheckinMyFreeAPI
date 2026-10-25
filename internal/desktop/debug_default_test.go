//go:build desktop && !desktoptest && (windows || linux)

package desktop

import "testing"

func TestReleaseDoesNotEnableRemoteDebuggingFromTestEnvironment(t *testing.T) {
	t.Setenv("CHECKIN_DESKTOP_TEST_CDP_PORT", "9229")
	if len(testBrowserArgs()) != 0 {
		t.Fatal("release accepted a test debugging port")
	}
}
