//go:build linux && !android

package settings

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
)

var (
	hasGSettings bool
	isKDE5       bool
	sudoUser     string
)

func init() {
	isKDE5 = common.Error(exec.LookPath("kwriteconfig5")) == nil
	hasGSettings = common.Error(exec.LookPath("gsettings")) == nil
	if os.Getuid() == 0 {
		sudoUser = os.Getenv("SUDO_USER")
	}
	if !hasGSettings && !hasKWriteConfig5 {
		return nil, E.New("unsupported desktop environment")
	}
	return &LinuxSystemProxy{
		hasGSettings:     hasGSettings,
		hasKWriteConfig5: hasKWriteConfig5,
		sudoUser:         sudoUser,
		serverAddr:       serverAddr,
		supportSOCKS:     supportSOCKS,
	}, nil
}

func (p *LinuxSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *LinuxSystemProxy) Enable() error {
	if p.hasGSettings {
		err := p.runAsUser("gsettings", "set", "org.gnome.system.proxy.http", "enabled", "true")
		if err != nil {
			return err
		}
		if p.supportSOCKS {
			err = p.setGnomeProxy("ftp", "http", "https", "socks")
		} else {
			err = p.setGnomeProxy("http", "https")
		}
		if err != nil {
			return err
		}
		err = p.runAsUser("gsettings", "set", "org.gnome.system.proxy", "use-same-proxy", F.ToString(p.supportSOCKS))
		if err != nil {
			return err
		}
		err = p.runAsUser("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
		if err != nil {
			return err
		}
	}
	if p.hasKWriteConfig5 {
		err := p.runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "ProxyType", "1")
		if err != nil {
			return err
		}
		if p.supportSOCKS {
			err = p.setKDEProxy("ftp", "http", "https", "socks")
		} else {
			err = p.setKDEProxy("http", "https")
		}
		if err != nil {
			return err
		}
		err = p.runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "Authmode", "0")
		if err != nil {
			return err
		}
		err = p.runAsUser("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		if err != nil {
			return err
		}
	}
	p.isEnabled = true
	return nil
}

func (p *LinuxSystemProxy) Disable() error {
	if p.hasGSettings {
		err := p.runAsUser("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
		if err != nil {
			return err
		}
	}
	if p.hasKWriteConfig5 {
		err := p.runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "ProxyType", "0")
		if err != nil {
			return err
		}
		err = p.runAsUser("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		if err != nil {
			return err
		}
	}
	p.isEnabled = false
	return nil
}

func (p *LinuxSystemProxy) runAsUser(name string, args ...string) error {
	if os.Getuid() != 0 {
		return shell.Exec(name, args...).Attach().Run()
	} else if p.sudoUser != "" {
		return shell.Exec("su", "-", p.sudoUser, "-c", F.ToString(name, " ", strings.Join(args, " "))).Attach().Run()
	} else {
		return E.New("set system proxy: unable to set as root")
	}
}

func SetSystemProxy(router adapter.Router, port uint16, isMixed bool) (func() error, error) {
	if hasGSettings {
		err := runAsUser("gsettings", "set", "org.gnome.system.proxy.http", "enabled", "true")
		if err != nil {
			return nil, err
		}
		if isMixed {
			err = setGnomeProxy(port, "ftp", "http", "https", "socks")
		} else {
			err = setGnomeProxy(port, "http", "https")
		}
		if err != nil {
			return nil, err
		}
		err = runAsUser("gsettings", "set", "org.gnome.system.proxy", "use-same-proxy", F.ToString(isMixed))
		if err != nil {
			return nil, err
		}
		err = runAsUser("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
		if err != nil {
			return nil, err
		}
		return func() error {
			return runAsUser("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
		}, nil
	}
	if isKDE5 {
		err := runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "ProxyType", "1")
		if err != nil {
			return nil, err
		}
		if isMixed {
			err = setKDEProxy(port, "ftp", "http", "https", "socks")
		} else {
			err = setKDEProxy(port, "http", "https")
		}
		if err != nil {
			return nil, err
		}
		err = runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "Authmode", "0")
		if err != nil {
			return nil, err
		}
		err = runAsUser("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		if err != nil {
			return nil, err
		}
		return func() error {
			err = runAsUser("kwriteconfig5", "--file", "kioslaverc", "--group", "'Proxy Settings'", "--key", "ProxyType", "0")
			if err != nil {
				return err
			}
			return runAsUser("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
		}, nil
	}
	return nil, E.New("unsupported desktop environment")
}

func setGnomeProxy(port uint16, proxyTypes ...string) error {
	for _, proxyType := range proxyTypes {
		err := p.runAsUser("gsettings", "set", "org.gnome.system.proxy."+proxyType, "host", p.serverAddr.AddrString())
		if err != nil {
			return err
		}
		err = p.runAsUser("gsettings", "set", "org.gnome.system.proxy."+proxyType, "port", F.ToString(p.serverAddr.Port))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *LinuxSystemProxy) setKDEProxy(proxyTypes ...string) error {
	for _, proxyType := range proxyTypes {
		var proxyUrl string
		if proxyType == "socks" {
			proxyUrl = "socks://" + p.serverAddr.String()
		} else {
			proxyUrl = "http://" + p.serverAddr.String()
		}
		err := p.runAsUser(
			"kwriteconfig5",
			"--file",
			"kioslaverc",
			"--group",
			"'Proxy Settings'",
			"--key", proxyType+"Proxy",
			proxyUrl,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func setKDEProxy(port uint16, proxyTypes ...string) error {
	for _, proxyType := range proxyTypes {
		var proxyUrl string
		if proxyType == "socks" {
			proxyUrl = "socks://127.0.0.1:" + F.ToString(port)
		} else {
			proxyUrl = "http://127.0.0.1:" + F.ToString(port)
		}
		err := runAsUser(
			"kwriteconfig5",
			"--file",
			"kioslaverc",
			"--group",
			"'Proxy Settings'",
			"--key", proxyType+"Proxy",
			proxyUrl,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
