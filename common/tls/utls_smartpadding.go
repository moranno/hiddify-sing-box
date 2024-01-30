//go:build with_utls

package tls

import (
	"io"
	"net"

	utls "github.com/sagernet/utls"
)

// FakeSmartPaddingExtension implements padding (0x15) extension. The padding data is another TLS client hello message
type FakeSmartPaddingExtension struct {
	*utls.GenericExtension
	// PaddingLen int
	FakeSNI string
	data    []byte // the actual fake bytes that will be read
	// WillPad bool   // set false to disable extension
}

// Len returns the length of the FakeSmartPaddingExtension.
func (e *FakeSmartPaddingExtension) Len() int {
	return 4 + len(e.data)
}

func NewFakeSmartPaddingExtension(fakesni string) *FakeSmartPaddingExtension {
	conn := new(net.TCPConn)
	uConn := utls.UClient(conn,
		&utls.Config{
			ServerName: fakesni,
		},
		utls.HelloRandomizedALPN)
	// create a new TLS client hello with a fake SNI
	c := utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER, // GREASE
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&SNIExtension{
				ServerName: fakesni,
			},
		},
	}
	_ = uConn.ApplyPreset(&c)
	_ = uConn.MarshalClientHello()
	rawHello := uConn.HandshakeState.Hello.Raw

	return &FakeSmartPaddingExtension{
		FakeSNI: fakesni,
		data:    rawHello,
	}
}

// Read reads the FakeSmartPaddingExtension.
func (e *FakeSmartPaddingExtension) Read(b []byte) (n int, err error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	b[0] = byte(tlsExtensionPadding >> 8)
	b[1] = byte(tlsExtensionPadding)
	b[2] = byte(len(e.data) >> 8)
	b[3] = byte(len(e.data))

	copy(b[4:], e.data)
	return e.Len(), io.EOF
}

// makeTLSHelloPacketWithSmartPadding creates a TLS hello packet with padding that looks like another TLS client hello with a given fake SNI
func makeTLSHelloPacketWithSmartPadding(conn net.Conn, e *UTLSClientConfig, sni string, fakesni string) (*utls.UConn, error) {

	uConn := utls.UClient(conn, e.config.Clone(), e.id)

	spec := utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_AES_128_GCM_SHA256, // tls 1.3
			utls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // pskModeDHE
			NewFakeSmartPaddingExtension(fakesni),
			&SNIExtension{
				ServerName: sni,
			},
		},
		GetSessionID: nil,
	}
	err := uConn.ApplyPreset(&spec)
	if err != nil {
		return nil, err
	}
	return uConn, nil
}
