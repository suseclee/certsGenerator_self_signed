package utils

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
//	"errors"
	"io/ioutil"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
//	"strings"
	"time"
)

type Certificate struct {
    CertDirPath string
}


// Comma-separated cnnames and IPs to generate a certificate for
// client will be stored in the client directory
func  GenerateCaCert(cnname string) ( *Certificate, error) {
    crt := new(Certificate)
    dir, err := ioutil.TempDir("/tmp", cnname)
    if err != nil {
	    return nil, err
    }
    fmt.Println(dir)
    crt.CertDirPath = dir
    fmt.Println(crt.CertDirPath)
    err = crt.CaCert(cnname)
	if err != nil {
	    return nil, err
	}
	return crt, nil
}

func (t *Certificate) CaCert(cnname string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"SUSE"},
			Country:       []string{"US"},
			Province:      []string{"WA"},
			Locality:      []string{"SEATTLE"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "tiller",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365*24*time.Hour),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca,  &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyToFile(path.Join(t.CertDirPath, "ca.key"), priv)
	certToFile(path.Join(t.CertDirPath, "/ca.crt"), ca_b)
	return nil
}

func (t *Certificate) GenerateClientCert(name string, cn string) error {
    // Load CA
    catls, err := tls.LoadX509KeyPair(path.Join(t.CertDirPath,"ca.crt"), path.Join(t.CertDirPath,"ca.key"))
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return err
	}
    // Check CN names
    if len(cn) == 0 {
	    return errors.New("Comma-separated cn names and IPs to generate a certificate for")
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"SUSE CAASP"},
			Country:       []string{"US"},
			Province:      []string{"WA"},
			Locality:      []string{"SEATTLE"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:   "tiller-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365*24*time.Hour),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cns := strings.Split(cn, ",")
	for _, h := range cns {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, h)
		}
	}
    priv, _ := rsa.GenerateKey(rand.Reader, 4096)

	cert_b, err := x509.CreateCertificate(rand.Reader, cert, ca, &priv.PublicKey, catls.PrivateKey)
	if err != nil {
		return err
	}
	keyToFile(path.Join(t.CertDirPath, name +".key"), priv)
	certToFile(path.Join(t.CertDirPath, name + ".crt"), cert_b)
	return nil
}

func keyToFile(filename string, key *rsa.PrivateKey) error {
	//keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	keyOut, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
    err = pem.Encode(keyOut, privateKey)
	if err!= nil {
		return err
	}
	return nil
}

func certToFile(filename string, ca []byte) error {
	certOut, err := os.Create(filename)
	defer certOut.Close()
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca}); err != nil {
		return err
	}
	return nil
}

