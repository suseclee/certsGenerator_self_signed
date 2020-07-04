package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type Certificate struct {
    name string
    cn string
    rootTemplate x509.Certificate
    rootKey *ecdsa.PrivateKey
    rootCrt *x509.Certificate
}

// Comma-separated cnnames and IPs to generate a certificate for
// client will be stored in the client directory
func  GenerateCerts(cn string, name string) {
    crt := Certificate {
        cn: cn,
        name: name,
    }
    if len(cn) == 0 {
	    log.Fatalf("Comma-separated cn names and IPs to generate a certificate for")
	}
    _ = os.Mkdir(name, 0755)
    crt.CaCrt()
    crt.ClientCrt()
	fmt.Printf("Successfully generated certificates in %s", name)
}

func (t *Certificate) CaCrt() {
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	keyToFile(t.name + "/ca.key", rootKey)
    t.rootKey = rootKey
	t.rootTemplate = x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SUSE"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365*24*time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	rootCrt, err := x509.CreateCertificate(rand.Reader, &t.rootTemplate, &t.rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(t.name + "/root.crt", rootCrt)
}

func (t *Certificate) ClientCrt(){
    clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	keyToFile(t.name + "/" + t.name +".key", clientKey)
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	clientTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SUSE BDD"},
			CommonName:   "bdd_cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365*24*time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}
	cns := strings.Split(t.cn, ",")
	for _, h := range cns {
		if ip := net.ParseIP(h); ip != nil {
			clientTemplate.IPAddresses = append(clientTemplate.IPAddresses, ip)
		} else {
			clientTemplate.DNSNames = append(clientTemplate.DNSNames, h)
		}
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &t.rootTemplate, &clientKey.PublicKey, t.rootKey)
	if err != nil {
		panic(err)
	}
	certToFile(t.name + "/" + t.name + ".crt", crtBytes)

}
func keyToFile(filename string, key *ecdsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing cert.pem: %s", err)
	}
}
