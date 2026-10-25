//go:build windows

package desktopcontrol

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsControlFileACLRetainsOwnerWithoutPublicGroups(t *testing.T) {
	dir, _, _ := fixture(t)
	path := filepath.Join(dir, FileName)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if !strings.Contains(sddl, "D:P") || strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;AU)") || strings.Contains(sddl, ";;;WD)") {
		t.Fatal("control ACL is not private", sddl)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// Make the record readable by Everyone. Discovery must fail closed even
	// when its capability and HMAC format are otherwise valid.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("public control ACL accepted", err)
	}
	if err = protectControl(path, dir); err != nil {
		t.Fatal(err)
	}
}
