package main

import (
	"flag"
	"net/http"
	"time"

	"github.com/floridoo/pod-ca-trust/pkg/env"
	"github.com/floridoo/pod-ca-trust/pkg/tls"
	"github.com/floridoo/pod-ca-trust/pkg/webhook"
	"k8s.io/klog/v2"
)

func main() {
	init := flag.Bool("init", false, "if set, run init logic")
	klog.InitFlags(flag.CommandLine)
	flag.Parse()

	if *init {
		err := tls.EnsureTSLCertificate(
			env.GetRequired("NAMESPACE"),
			env.GetRequired("SECRET_NAME"),
			env.GetRequired("WEBHOOK_NAME"),
			env.GetRequired("DNS_NAME"),
		)
		if err != nil {
			klog.Fatal(err)
		}
		return
	}

	config := webhook.CAInjectionWebhookConfig{
		CACert:      env.GetRequired("CA_CERT"),
		CAMountPath: env.GetWithDefault("CA_MOUNT_PATH", "/etc/ssl/certs/injected-ca.pem"),
	}
	handler, err := webhook.New(config)
	if err != nil {
		klog.Fatal(err)
	}

	s := &http.Server{
		Addr:           env.GetWithDefault("LISTEN", ":8443"),
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	klog.Infof("Listening on %q", s.Addr)
	err = s.ListenAndServeTLS(
		env.GetRequired("SERVE_TLS_CERT"),
		env.GetRequired("SERVE_TLS_KEY"),
	)
	if err != nil {
		klog.Fatal(err)
	}
}
