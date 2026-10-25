//go:build windows

package platform

import "golang.org/x/sys/windows"

// ProtectFile restricts newly-created credential files even in a shared parent.
func ProtectFile(path string) error      { return protect(path, false) }
func protectDirectory(path string) error { return protect(path, true) }
func protect(path string, directory bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;BA)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")"
	descriptor, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	acl, _, e := descriptor.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
