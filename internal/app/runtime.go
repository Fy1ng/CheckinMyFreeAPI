package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

type RuntimeSettings struct {
	Revision            int  `json:"revision"`
	RunOnStartup        bool `json:"run_on_startup"`
	StartupDelaySeconds int  `json:"startup_delay_seconds"`
}
type RuntimeConfig struct {
	mu       sync.Mutex
	path     string
	settings RuntimeSettings
}

func OpenRuntime(dataDir string) (*RuntimeConfig, error) {
	r := &RuntimeConfig{path: filepath.Join(dataDir, "go-runtime.json"), settings: RuntimeSettings{RunOnStartup: true, StartupDelaySeconds: 10}}
	if e := platform.PrivateFile(r.path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(r.path)
	if os.IsNotExist(e) {
		return r, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 4096 {
		return nil, errors.New("本机启动配置超出大小限制")
	}
	if e = json.Unmarshal(b, &r.settings); e != nil {
		return nil, errors.New("本机启动配置无效")
	}
	if r.settings.Revision < 0 || r.settings.StartupDelaySeconds < 0 || r.settings.StartupDelaySeconds > 300 {
		return nil, errors.New("本机启动配置无效")
	}
	return r, nil
}
func (r *RuntimeConfig) Get() RuntimeSettings { r.mu.Lock(); defer r.mu.Unlock(); return r.settings }
func (r *RuntimeConfig) Save(next RuntimeSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if next.Revision != r.settings.Revision {
		return errors.New("启动配置已更新, 请重新读取")
	}
	if next.StartupDelaySeconds < 0 || next.StartupDelaySeconds > 300 {
		return errors.New("启动等待时间须为 0 至 300 秒")
	}
	next.Revision++
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if e = platform.PrivateFile(r.path); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(r.path), ".runtime-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, r.path); e != nil {
		return e
	}
	r.settings = next
	return nil
}
