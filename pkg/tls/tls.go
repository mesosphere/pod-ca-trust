package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/wI2L/jsondiff"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreapply "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const certificateExpiration = 10 * 365 * 24 * time.Hour // 10 years

func EnsureTSLCertificate(namespace, secretName, webhookName, dnsName string) error {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return err
	}
	ctx := context.Background()

	// generate a TLS key pair
	privateKey, publicKey, err := getKeyPair(dnsName)
	if err != nil {
		return err
	}

	// write the certificate into a Secret
	_, err = clientset.CoreV1().Secrets(namespace).Apply(ctx,
		coreapply.Secret(secretName, namespace).
			WithType(core.SecretTypeTLS).
			WithData(map[string][]byte{
				core.TLSPrivateKeyKey: privateKey,
				core.TLSCertKey:       publicKey,
				"ca.crt":              publicKey,
			}),
		meta.ApplyOptions{FieldManager: "pod-ca-trust-tls-init", Force: true},
	)
	if err != nil {
		return err
	}

	// update the Admission Webhook with the certificate's CA (== public key, because self-signed)
	patch, _ := json.Marshal(&jsondiff.Patch{{
		Type:  jsondiff.OperationReplace,
		Path:  "/webhooks/0/clientConfig/caBundle",
		Value: base64.StdEncoding.EncodeToString(publicKey),
	}})
	_, err = clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(
		ctx, webhookName, types.JSONPatchType, patch, meta.PatchOptions{FieldManager: "pod-ca-trust-tls-init"},
	)
	if err != nil {
		return err
	}
	return nil
}

func getKeyPair(dnsName string) (private, public []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pod-ca-trust-webhook",
		},
		DNSNames: []string{dnsName},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certificateExpiration),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicBuf := &bytes.Buffer{}
	err = pem.Encode(publicBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, err
	}

	privateBuf := &bytes.Buffer{}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	err = pem.Encode(privateBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	if err != nil {
		return nil, nil, err
	}

	return privateBuf.Bytes(), publicBuf.Bytes(), nil
}
