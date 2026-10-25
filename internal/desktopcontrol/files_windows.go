//go:build windows

package desktopcontrol

import (
	"os"
	"strings"
	"unsafe"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"golang.org/x/sys/windows"
)

// The directory owner already controls this configuration and its master key.
// Keep that one SID when a LocalSystem service creates the control file, without
// copying inherited Users/Everyone/AuthUsers access from a shared parent.
func controlSIDs(dataDir string) (map[string]bool, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, ErrUntrusted
	}
	allowed := map[string]bool{user.User.Sid.String(): true, "S-1-5-18": true, "S-1-5-32-544": true}
	descriptor, err := windows.GetNamedSecurityInfo(dataDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return nil, ErrUntrusted
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return nil, ErrUntrusted
	}
	sid := owner.String()
	if !allowed[sid] && !strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasPrefix(sid, "S-1-5-80-") {
		return nil, ErrUntrusted
	}
	allowed[sid] = true
	return allowed, nil
}

func protectControl(path, dataDir string) error {
	if err := platform.ProtectFile(path); err != nil {
		return err
	}
	allowed, err := controlSIDs(dataDir)
	if err != nil {
		return err
	}
	sddl := "D:P"
	for sid := range allowed {
		sddl += "(A;;FA;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func openControl(path, dataDir string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrUntrusted
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUnavailable
		}
		return nil, ErrUntrusted
	}
	f := os.NewFile(uintptr(handle), path)
	bad := func() (*os.File, error) { f.Close(); return nil, ErrUntrusted }
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return bad()
	}
	allowed, err := controlSIDs(dataDir)
	if err != nil {
		return bad()
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return bad()
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !allowed[owner.String()] {
		return bad()
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return bad()
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil {
			return bad()
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return bad()
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[sid.String()] {
			return bad()
		}
	}
	return f, nil
}
