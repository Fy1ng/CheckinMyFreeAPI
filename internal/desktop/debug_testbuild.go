//go:build desktop && desktoptest && (windows || linux)

package desktop

import (
	"os"
	"strconv"
)

func testBrowserArgs() []string {
	port, e := strconv.Atoi(os.Getenv("CHECKIN_DESKTOP_TEST_CDP_PORT"))
	if e != nil || port < 1024 || port > 65535 {
		return nil
	}
	return []string{"--remote-debugging-address=127.0.0.1", "--remote-debugging-port=" + strconv.Itoa(port)}
}
