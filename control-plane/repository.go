package example

import (
	"fmt"
	"os"
)

var serverNames = []string{
	"apple.example.com",
	"banana.example.com",
}

type ClientCertValidationContext struct {
	ServerName string
	CACert     []byte
}

type ServerKeyPair struct {
	Cert []byte
	Key  []byte
}

func GetClientCertValidationContexts() []*ClientCertValidationContext {
	var valContexts []*ClientCertValidationContext
	for _, serverName := range serverNames {
		caCert, err := os.ReadFile(fmt.Sprintf("certs/%s/ca.pem", serverName))
		if err != nil {
			panic(err)
		}
		valContexts = append(
			valContexts,
			&ClientCertValidationContext{
				ServerName: serverName,
				CACert:     caCert,
			},
		)
	}
	return valContexts
}

func GetServerKeyPair() *ServerKeyPair {
	serverCert, err := os.ReadFile("certs/server.pem")
	if err != nil {
		panic(err)
	}
	serverKey, err := os.ReadFile("certs/server-key.pem")
	if err != nil {
		panic(err)
	}
	return &ServerKeyPair{
		Cert: serverCert,
		Key:  serverKey,
	}
}
