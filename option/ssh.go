package option

type SSHOutboundOptions struct {
	DialerOptions
	ServerOptions
	User                 string             `json:"user,omitempty"`
	Password             string             `json:"password,omitempty"`
	PrivateKey           Listable[string]   `json:"private_key,omitempty"`
	PrivateKeyPath       string             `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string             `json:"private_key_passphrase,omitempty"`
	HostKey              Listable[string]   `json:"host_key,omitempty"`
	HostKeyAlgorithms    Listable[string]   `json:"host_key_algorithms,omitempty"`
	ClientVersion        string             `json:"client_version,omitempty"`
	UDPOverTCP           *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	Network              NetworkList        `json:"network,omitempty"`
}

type SSHUser struct {
	Name      string `json:"name"`
	User      string `json:"user"`
	Password  string `json:"password,omitempty"`
	PublicKey string `json:"private_key,omitempty"`
}

type SSHInboundOptions struct {
	ListenOptions
	Users             []SSHUser        `json:"users,omitempty"`
	HostKey           Listable[string] `json:"host_key,omitempty"`
	HostKeyAlgorithms Listable[string] `json:"host_key_algorithms,omitempty"`
	Network           NetworkList      `json:"network,omitempty"`
	ClientVersion     string           `json:"client_version,omitempty"`
}
