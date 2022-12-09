package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/floridoo/pod-ca-trust/pkg/webhook"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(flag.CommandLine)
	flag.Parse()

	config := webhook.CAInjectionWebhookConfig{
		CASecretName:      getEnvRequired("CA_SECRET_NAME"),
		CASecretNamespace: getEnvRequired("CA_SECRET_NAMESPACE"),
		CASecretKey:       getEnvWithDefault("CA_SECRET_KEY", "ca.crt"),
		CABundlePath:      getEnvWithDefault("CA_BUNDLE_PATH", "/etc/ssl/certs/injected-ca.pem"),
	}
	handler, err := webhook.New(config)
	if err != nil {
		klog.Fatal(err)
	}

	s := &http.Server{
		Addr:           getEnvWithDefault("LISTEN", ":8443"),
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	klog.Infof("Listening on %q", s.Addr)
	err = s.ListenAndServeTLS(
		getEnvRequired("SERVE_TLS_CERT"),
		getEnvRequired("SERVE_TLS_KEY"),
	)
	if err != nil {
		klog.Fatal(err)
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	env, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}
	return env
}

func getEnvRequired(key string) string {
	env, ok := os.LookupEnv(key)
	if !ok {
		klog.Fatalf("ENV variable $%s must be set\n", key)
	}
	return env
}
