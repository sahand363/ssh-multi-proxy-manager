package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows/registry"
)

const (
	AppVersion = "1.07"
	AppID      = "sahand_ssh_multi_proxy_manager"
	PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGIpBbSIsm8l8DnrzpiJuuHoNsSppS4RURVWy06rngPk=
-----END PUBLIC KEY-----`
)

// --- Custom Modern Dark Theme ---

type darkSlateTheme struct{}

func (d darkSlateTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return color.RGBA{R: 15, G: 23, B: 42, A: 255} // #0F172A
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 30, G: 41, B: 59, A: 255} // #1E293B
	case theme.ColorNamePrimary:
		return color.RGBA{R: 31, G: 83, B: 141, A: 255} // #1F538D
	case theme.ColorNameButton:
		return color.RGBA{R: 30, G: 41, B: 59, A: 255}
	case theme.ColorNameForeground:
		return color.RGBA{R: 241, G: 245, B: 249, A: 255}
	case theme.ColorNamePlaceHolder:
		return color.RGBA{R: 148, G: 163, B: 184, A: 255}
	default:
		return theme.DefaultTheme().Color(n, theme.VariantDark)
	}
}
func (d darkSlateTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (d darkSlateTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (d darkSlateTheme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) }

// --- Models ---

type Profile struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Port      string `json:"port"`
	User      string `json:"user"`
	Password  string `json:"password"`
	LocalPort string `json:"local_port"`
	Selected  bool   `json:"selected"`
}

type LicenseData struct {
	FirstRun    int64  `json:"first_run"`
	Expiry      int64  `json:"expiry"`
	Client      string `json:"client"`
	IsActivated bool   `json:"is_activated"`
}

type LicensePayload struct {
	AppID     string `json:"app_id"`
	IssuedAt  int64  `json:"issued_at"`
	ValidDays int    `json:"valid_days"`
	Client    string `json:"client"`
}

type SerialBlob struct {
	Payload LicensePayload `json:"payload"`
	Sig     string         `json:"sig"`
}

// --- Windows System Proxy Controller ---

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func setSystemProxy(enable bool, host string, port int) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if enable {
		proxyVal := fmt.Sprintf("socks=%s:%d", host, port)
		_ = k.SetDWordValue("ProxyEnable", 1)
		_ = k.SetStringValue("ProxyServer", proxyVal)
	} else {
		_ = k.SetDWordValue("ProxyEnable", 0)
	}

	// 39 = INTERNET_OPTION_SETTINGS_CHANGED, 37 = INTERNET_OPTION_REFRESH
	procInternetSetOptionW.Call(0, 39, 0, 0)
	procInternetSetOptionW.Call(0, 37, 0, 0)
	return nil
}

// --- License Manager ---

type LicenseManager struct {
	fileDir string
	licFile string
}

func NewLicenseManager() *LicenseManager {
	localApp := os.Getenv("LOCALAPPDATA")
	if localApp == "" {
		localApp, _ = os.UserHomeDir()
	}
	dir := filepath.Join(localApp, "SahandSSHProxy")
	return &LicenseManager{
		fileDir: dir,
		licFile: filepath.Join(dir, "license.dat"),
	}
}

func (lm *LicenseManager) Save(data LicenseData) {
	_ = os.MkdirAll(lm.fileDir, 0755)
	raw, _ := json.Marshal(data)
	enc := base64.StdEncoding.EncodeToString(raw)
	_ = os.WriteFile(lm.licFile, []byte(enc), 0644)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\SahandSSHProxy\Vault`, registry.SET_VALUE)
	if err == nil {
		_ = k.SetStringValue("LicData", enc)
		k.Close()
	}
}

func (lm *LicenseManager) Load() LicenseData {
	var enc string
	if b, err := os.ReadFile(lm.licFile); err == nil {
		enc = strings.TrimSpace(string(b))
	}
	if enc == "" {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\SahandSSHProxy\Vault`, registry.QUERY_VALUE)
		if err == nil {
			enc, _, _ = k.GetStringValue("LicData")
			k.Close()
		}
	}
	if enc != "" {
		if raw, err := base64.StdEncoding.DecodeString(enc); err == nil {
			var ld LicenseData
			if json.Unmarshal(raw, &ld) == nil {
				return ld
			}
		}
	}
	now := time.Now().Unix()
	ld := LicenseData{
		FirstRun:    now,
		Expiry:      now + (30 * 86400),
		Client:      "Trial User",
		IsActivated: false,
	}
	lm.Save(ld)
	return ld
}

func (lm *LicenseManager) Verify(serial string) (bool, string) {
	block, _ := pem.Decode([]byte(PublicKeyPEM))
	if block == nil {
		return false, "Invalid Public Key"
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, "Public Key Parsing Error"
	}
	pubKey := pubInterface.(ed25519.PublicKey)

	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, serial)

	padLen := (8 - (len(clean) % 8)) % 8
	clean += strings.Repeat("=", padLen)

	rawBlob, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return false, "Invalid Serial Number Format"
	}

	var blob SerialBlob
	if err := json.Unmarshal(rawBlob, &blob); err != nil {
		return false, "Corrupted Serial Payload"
	}

	if blob.Payload.AppID != AppID {
		return false, "Serial Key is not valid for this application!"
	}

	sigBytes, err := base64.StdEncoding.DecodeString(blob.Sig)
	if err != nil {
		return false, "Invalid Signature Encoding"
	}

	// Canonical payload serialization with sorted keys
	canonicalJSON := fmt.Sprintf(`{"app_id":"%s","client":"%s","issued_at":%d,"valid_days":%d}`,
		blob.Payload.AppID, blob.Payload.Client, blob.Payload.IssuedAt, blob.Payload.ValidDays)

	if !ed25519.Verify(pubKey, []byte(canonicalJSON), sigBytes) {
		return false, "Cryptographic Signature Mismatch!"
	}

	expiry := blob.Payload.IssuedAt + int64(blob.Payload.ValidDays*86400)
	lm.Save(LicenseData{
		FirstRun:    blob.Payload.IssuedAt,
		Expiry:      expiry,
		Client:      blob.Payload.Client,
		IsActivated: true,
	})
	return true, "Successfully Activated!"
}

// --- SOCKS5 Server & SSH Tunnel Engine ---

type TunnelInstance struct {
	Name       string
	Cancel     context.CancelFunc
	Listener   net.Listener
	SSHClient  *ssh.Client
	LocalPort  int
	KeepAlive  bool
	AutoRec    bool
	IsConnected bool
}

func handleSocksConnection(conn net.Conn, sshClient *ssh.Client) {
	defer conn.Close()
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // No auth

	if _, err := io.ReadFull(conn, buf[:4]); err != nil || buf[1] != 0x01 {
		return // CONNECT command only
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, buf[:4])
		host = net.IP(buf[:4]).String()
	case 0x03: // FQDN
		io.ReadFull(conn, buf[:1])
		dLen := int(buf[0])
		io.ReadFull(conn, buf[:dLen])
		host = string(buf[:dLen])
	case 0x04: // IPv6
		io.ReadFull(conn, buf[:16])
		host = net.IP(buf[:16]).String()
	default:
		return
	}

	io.ReadFull(conn, buf[:2])
	port := int(buf[0])<<8 | int(buf[1])
	target := fmt.Sprintf("%s:%d", host, port)

	remoteConn, err := sshClient.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	errChan := make(chan error, 2)
	go func() { _, err := io.Copy(remoteConn, conn); errChan <- err }()
	go func() { _, err := io.Copy(conn, remoteConn); errChan <- err }()
	<-errChan
}

// --- Main Application GUI ---

type AppState struct {
	profiles        map[string]Profile
	tunnels         map[string]*TunnelInstance
	activeSysProxy  string
	licManager      *LicenseManager
	logBinding      *widget.Entry
	statusLabel     *widget.Label
	vmLabel         *widget.Label
	cardContainer   *fyne.Container
	checkboxContainer *fyne.Container
	mu              sync.Mutex
	window          fyne.Window
}

func (s *AppState) Log(msg string) {
	ts := time.Now().Format("[15:04:05]")
	fullMsg := fmt.Sprintf("%s %s\n", ts, msg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.logBinding != nil {
		s.logBinding.SetText(s.logBinding.Text + fullMsg)
	}
}

func (s *AppState) SaveProfiles() {
	raw, _ := json.MarshalIndent(s.profiles, "", "  ")
	_ = os.WriteFile("profiles.json", raw, 0644)
}

func (s *AppState) LoadProfiles() {
	s.profiles = make(map[string]Profile)
	if data, err := os.ReadFile("profiles.json"); err == nil {
		_ = json.Unmarshal(data, &s.profiles)
	}
}

func getHostIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	if len(ips) == 0 {
		return []string{"127.0.0.1"}
	}
	return ips
}

func main() {
	a := app.NewWithID("com.sahand.sshproxy")
	a.Settings().SetTheme(&darkSlateTheme{})

	w := a.NewWindow(fmt.Sprintf("Sahand SSH Multi-Proxy Manager v%s", AppVersion))
	w.Resize(fyne.NewSize(740, 680))

	state := &AppState{
		tunnels:    make(map[string]*TunnelInstance),
		licManager: NewLicenseManager(),
		window:     w,
	}
	state.LoadProfiles()

	// Header
	title := widget.NewLabelWithStyle(fmt.Sprintf("Sahand SSH Multi-Proxy Manager v%s", AppVersion), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	statusBox := widget.NewLabelWithStyle("STATUS: READY", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	state.statusLabel = statusBox

	// About Dialog Button
	btnAbout := widget.NewButtonWithIcon("About", theme.InfoIcon(), func() {
		showAboutDialog(state)
	})

	// Log Viewer Box
	state.logBinding = widget.NewMultiLineEntry()
	state.logBinding.Wrapping = fyne.TextWrapWord
	state.logBinding.SetMinRowsVisible(6)

	// VM Guide Display
	hostIPs := strings.Join(getHostIPs(), " or ")
	state.vmLabel = widget.NewLabel(fmt.Sprintf("💻 VM SOCKS Address: %s | Port: [Active SOCKS Port]", hostIPs))

	// Profile Configuration Inputs
	entryName := widget.NewEntry()
	entryName.SetPlaceHolder("Profile Name (e.g. US-East)")
	entryHost := widget.NewEntry()
	entryHost.SetPlaceHolder("Server IP / Host")
	entryPort := widget.NewEntry()
	entryPort.SetText("22")
	entryUser := widget.NewEntry()
	entryUser.SetPlaceHolder("Username (e.g. root)")
	entryPass := widget.NewPasswordEntry()
	entryPass.SetPlaceHolder("Password")
	entryLocalPort := widget.NewEntry()
	entryLocalPort.SetText("1337")

	form := container.NewVBox(
		entryName,
		entryHost,
		entryPort,
		entryUser,
		entryPass,
		entryLocalPort,
	)

	state.cardContainer = container.NewVBox()
	state.checkboxContainer = container.NewVBox()

	btnSave := widget.NewButtonWithIcon("Save Profile", theme.DocumentSaveIcon(), func() {
		name := strings.TrimSpace(entryName.Text)
		if name == "" {
			dialog.ShowError(fmt.Errorf("Profile name is required"), w)
			return
		}
		state.profiles[name] = Profile{
			Name:      name,
			IP:        strings.TrimSpace(entryHost.Text),
			Port:      strings.TrimSpace(entryPort.Text),
			User:      strings.TrimSpace(entryUser.Text),
			Password:  strings.TrimSpace(entryPass.Text),
			LocalPort: strings.TrimSpace(entryLocalPort.Text),
			Selected:  state.profiles[name].Selected,
		}
		state.SaveProfiles()
		state.RefreshProfileList()
		state.Log(fmt.Sprintf("[Config] Saved profile '%s'", name))
	})

	btnDelete := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		name := strings.TrimSpace(entryName.Text)
		if name != "" {
			state.StopTunnel(name)
			delete(state.profiles, name)
			state.SaveProfiles()
			state.RefreshProfileList()
			state.Log(fmt.Sprintf("[Config] Deleted profile '%s'", name))
		}
	})

	profileControls := container.NewGridWithColumns(2, btnSave, btnDelete)
	leftCol := container.NewVBox(
		widget.NewLabelWithStyle("Add / Edit Server", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		form,
		profileControls,
	)

	rightCol := container.NewVBox(
		widget.NewLabelWithStyle("Select Profiles to Connect:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewVScroll(state.checkboxContainer),
	)

	mainRow := container.NewGridWithColumns(2, leftCol, rightCol)

	btnConnectAll := widget.NewButtonWithIcon("CONNECT ALL SELECTED", theme.MediaPlayIcon(), func() {
		for name, p := range state.profiles {
			if p.Selected {
				go state.StartTunnel(name)
			}
		}
	})
	btnConnectAll.Importance = widget.HighImportance

	btnClearLog := widget.NewButtonWithIcon("Clear Logs", theme.ContentClearIcon(), func() {
		state.logBinding.SetText("")
	})

	topBar := container.NewBorder(nil, nil, title, btnAbout)

	content := container.NewVBox(
		topBar,
		widget.NewSeparator(),
		mainRow,
		state.vmLabel,
		statusBox,
		btnConnectAll,
		widget.NewLabelWithStyle("Active Server Connections:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		state.cardContainer,
		container.NewBorder(nil, nil, widget.NewLabelWithStyle(" PuTTY Activity Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), btnClearLog),
		state.logBinding,
	)

	state.RefreshProfileList()
	state.Log(fmt.Sprintf("[System] Application initialized successfully (Version v%s)", AppVersion))

	w.SetContent(container.NewVScroll(content))
	w.SetOnClosed(func() {
		_ = setSystemProxy(false, "", 0)
		for name := range state.tunnels {
			state.StopTunnel(name)
		}
	})

	w.ShowAndRun()
}

func (s *AppState) RefreshProfileList() {
	s.checkboxContainer.Objects = nil
	keys := make([]string, 0, len(s.profiles))
	for k := range s.profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		p := s.profiles[name]
		chk := widget.NewCheck(fmt.Sprintf("%s (Port: %s)", p.Name, p.LocalPort), func(checked bool) {
			prof := s.profiles[name]
			prof.Selected = checked
			s.profiles[name] = prof
			s.SaveProfiles()
			s.RebuildConnectionCards()
		})
		chk.SetChecked(p.Selected)
		s.checkboxContainer.Add(chk)
	}
	s.checkboxContainer.Refresh()
	s.RebuildConnectionCards()
}

func (s *AppState) RebuildConnectionCards() {
	s.cardContainer.Objects = nil

	for name, p := range s.profiles {
		if !p.Selected {
			continue
		}
		profName := name
		lPort := p.LocalPort

		dot := widget.NewLabel("●")
		dot.TextStyle = fyne.TextStyle{Bold: true}

		info := widget.NewLabel(fmt.Sprintf("%s ➔ SOCKS: %s", profName, lPort))
		btnConnect := widget.NewButton("Connect", nil)
		btnWinProxy := widget.NewButton("Win Proxy", nil)
		autoRecCheck := widget.NewCheck("Auto-Reconnect", nil)
		autoRecCheck.SetChecked(true)

		tun, active := s.tunnels[profName]
		if active && tun.IsConnected {
			dot.SetText("🟢")
			btnConnect.SetText("Disconnect")
			btnWinProxy.Enable()
		} else {
			dot.SetText("⚪")
			btnConnect.SetText("Connect")
			btnWinProxy.Disable()
		}

		if s.activeSysProxy == profName {
			btnWinProxy.SetText("Unset Proxy")
		} else {
			btnWinProxy.SetText("Win Proxy")
		}

		btnConnect.OnTapped = func() {
			if _, running := s.tunnels[profName]; running {
				s.StopTunnel(profName)
			} else {
				go s.StartTunnel(profName)
			}
		}

		btnWinProxy.OnTapped = func() {
			portInt, _ := strconv.Atoi(lPort)
			if s.activeSysProxy == profName {
				_ = setSystemProxy(false, "127.0.0.1", portInt)
				s.activeSysProxy = ""
				s.Log(fmt.Sprintf("[Proxy] Windows System Proxy DISABLED for '%s'", profName))
			} else {
				_ = setSystemProxy(true, "127.0.0.1", portInt)
				s.activeSysProxy = profName
				s.Log(fmt.Sprintf("[Proxy] Windows System Proxy set to 127.0.0.1:%d", portInt))
			}
			s.RebuildConnectionCards()
		}

		autoRecCheck.OnChanged = func(val bool) {
			if t, ok := s.tunnels[profName]; ok {
				t.AutoRec = val
			}
		}

		row := container.NewHBox(dot, info, autoRecCheck, btnWinProxy, btnConnect)
		s.cardContainer.Add(row)
	}
	s.cardContainer.Refresh()
}

func (s *AppState) StartTunnel(name string) {
	p, ok := s.profiles[name]
	if !ok {
		return
	}

	localPort, _ := strconv.Atoi(p.LocalPort)
	if localPort == 0 {
		localPort = 1337
	}

	ctx, cancel := context.WithCancel(context.Background())
	tun := &TunnelInstance{
		Name:      name,
		Cancel:    cancel,
		LocalPort: localPort,
		KeepAlive: true,
		AutoRec:   true,
	}

	s.mu.Lock()
	s.tunnels[name] = tun
	s.mu.Unlock()

	s.RebuildConnectionCards()
	s.statusLabel.SetText(fmt.Sprintf("STATUS: CONNECTING TO %s...", name))

	for tun.KeepAlive {
		s.Log(fmt.Sprintf("=================================================="))
		s.Log(fmt.Sprintf("[PuTTY Log] Connecting to host %s port %s...", p.IP, p.Port))

		sshConfig := &ssh.ClientConfig{
			User:            p.User,
			Auth:            []ssh.AuthMethod{ssh.Password(p.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", p.IP, p.Port), sshConfig)
		if err != nil {
			s.Log(fmt.Sprintf("[ERROR] SSH connection failed: %v", err))
		} else {
			s.Log(fmt.Sprintf("[PuTTY Log] Connected to %s over SSH v2.0", p.IP))
			tun.SSHClient = client

			listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", localPort))
			if err != nil {
				s.Log(fmt.Sprintf("[ERROR] SOCKS binding failed on port %d: %v", localPort, err))
				client.Close()
			} else {
				tun.Listener = listener
				tun.IsConnected = true
				s.Log(fmt.Sprintf("[SOCKS5] Serving traffic on 0.0.0.0:%d", localPort))
				s.statusLabel.SetText("STATUS: CONNECTED")
				s.RebuildConnectionCards()

				// Connection listener loop
				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						go handleSocksConnection(conn, client)
					}
				}()

				// Keepalive heartbeats
				for tun.KeepAlive {
					time.Sleep(15 * time.Second)
					_, _, err := client.SendRequest("keepalive@golang.org", true, nil)
					if err != nil {
						s.Log(fmt.Sprintf("[Error] Keepalive dropped for '%s'", name))
						break
					}
				}
				listener.Close()
			}
			client.Close()
		}

		tun.IsConnected = false
		s.RebuildConnectionCards()

		if !tun.KeepAlive || !tun.AutoRec {
			break
		}

		s.statusLabel.SetText(fmt.Sprintf("STATUS: RECONNECTING (%s)...", name))
		s.Log(fmt.Sprintf("[Auto-Reconnect] Retrying in 5 seconds..."))
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}

	s.StopTunnel(name)
}

func (s *AppState) StopTunnel(name string) {
	s.mu.Lock()
	tun, exists := s.tunnels[name]
	if exists {
		tun.KeepAlive = false
		tun.AutoRec = false
		if tun.Cancel != nil {
			tun.Cancel()
		}
		if tun.Listener != nil {
			tun.Listener.Close()
		}
		if tun.SSHClient != nil {
			tun.SSHClient.Close()
		}
		delete(s.tunnels, name)
	}
	s.mu.Unlock()

	if s.activeSysProxy == name {
		_ = setSystemProxy(false, "", 0)
		s.activeSysProxy = ""
	}

	s.statusLabel.SetText("STATUS: READY")
	s.Log(fmt.Sprintf("[System] Closed connection '%s'", name))
	s.RebuildConnectionCards()
}

func showAboutDialog(state *AppState) {
	lic := state.licManager.Load()
	rem := lic.Expiry - time.Now().Unix()
	var timeText string
	if rem <= 0 {
		timeText = "EXPIRED / TRIAL ENDED!"
	} else {
		prefix := "TRIAL:"
		if lic.IsActivated {
			prefix = "FULL LICENSE:"
		}
		timeText = fmt.Sprintf("%s %dd %02dh remaining", prefix, rem/86400, (rem%86400)/3600)
	}

	statusLabel := widget.NewLabelWithStyle(timeText, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	serialEntry := widget.NewMultiLineEntry()
	serialEntry.SetPlaceHolder("Paste Base32 activation serial key here...")

	btnActivate := widget.NewButton("Activate Serial Key", func() {
		ok, msg := state.licManager.Verify(serialEntry.Text)
		if ok {
			dialog.ShowInformation("License", msg, state.window)
		} else {
			dialog.ShowError(fmt.Errorf("%s", msg), state.window)
		}
	})

	box := container.NewVBox(
		widget.NewLabelWithStyle("Sahand SSH Multi-Proxy Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("Version %s (Go & Fyne Edition)", AppVersion)),
		widget.NewLabel("Support: sahand363@gmail.com"),
		widget.NewSeparator(),
		statusLabel,
		widget.NewLabel("Enter Activation Key:"),
		serialEntry,
		btnActivate,
	)

	d := dialog.NewCustom("About & Licensing", "Close", box, state.window)
	d.Resize(fyne.NewSize(450, 400))
	d.Show()
}
