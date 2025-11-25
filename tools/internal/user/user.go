//go:build darwin
// +build darwin

package user

import (
	"os/user"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"
)

/*
#cgo LDFLAGS: -framework SystemConfiguration
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>

void GetConsoleUser(char **username, uid_t *uid, gid_t *gid) {
    CFStringRef user;
    SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("GetConsoleUser"), NULL, NULL);
    if (store == NULL) {
        *username = NULL;
        return;
    }
    user = SCDynamicStoreCopyConsoleUser(store, uid, gid);
    if (user == NULL) {
        CFRelease(store);
        *username = NULL;
        return;
    }
    CFIndex length = CFStringGetLength(user);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    *username = (char *)malloc(maxSize);
    if (CFStringGetCString(user, *username, maxSize, kCFStringEncodingUTF8)) {
        CFRelease(user);
        CFRelease(store);
        return;
    }
    free(*username);
    *username = NULL;
    CFRelease(user);
    CFRelease(store);
}
*/
import "C"

type ConsoleUser struct {
	username string
	uid      int
	gid      int
}

// GetConsoleUser returns a ConsoleUser struct. This can be used to get the
// current console user's username, group name, or user and group IDs.
// GetConsoleUser retrieves the name, UID, and GID of the current console user.
func GetConsoleUser() (ConsoleUser, error) {
	var (
		cUsername *C.char
		cUID      C.uid_t
		cGID      C.gid_t
	)
	C.GetConsoleUser(&cUsername, &cUID, &cGID)
	if cUsername == nil {
		return ConsoleUser{}, errors.New("failed to get console user")
	}
	defer C.free(unsafe.Pointer(cUsername))
	return ConsoleUser{
		username: C.GoString(cUsername),
		uid:      int(cUID),
		gid:      int(cGID),
	}, nil
}

func (c *ConsoleUser) GroupID() int {
	return c.gid
}

func (c *ConsoleUser) GroupName() (string, error) {
	grp, err := c.group()
	if err != nil {
		return "", errors.Wrap(err, "could not get group")
	}

	return grp.Name, nil
}

func (c *ConsoleUser) HomeDirectory() (string, error) {
	usr, err := c.user()
	if err != nil {
		return "", errors.Wrap(err, "could not get user")
	}

	return usr.HomeDir, nil
}

func (c *ConsoleUser) group() (*user.Group, error) {
	grp, err := user.LookupGroupId(strconv.Itoa(c.gid))
	if err != nil {
		return nil, errors.Wrap(err, "could not look up group")
	}

	return grp, nil
}

func (c *ConsoleUser) UserID() int {
	return c.uid
}

func (c *ConsoleUser) UserName() string {
	return c.username
}

func (c *ConsoleUser) user() (*user.User, error) {
	usr, err := user.LookupId(strconv.Itoa(c.uid))
	if err != nil {
		return nil, errors.Wrap(err, "could not look up user")
	}

	return usr, nil
}
