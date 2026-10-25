package desktop

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed navigation.js
var navigationSource string

func navigationScript(origin string) string {
	encoded, _ := json.Marshal(origin)
	return strings.Replace(navigationSource, "__CHECKIN_DESKTOP_ORIGIN__", string(encoded), 1)
}
