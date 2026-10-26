package desktop

import (
	"sync"

	frontend "github.com/Fy1ng/CheckinMyFreeAPI/server"
)

var appIcon = sync.OnceValue(func() []byte {
	icon, err := frontend.Files.ReadFile("static/logo.png")
	if err != nil {
		panic("embedded desktop logo is unavailable")
	}
	return icon
})
