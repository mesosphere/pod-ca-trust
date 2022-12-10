package env

import (
	"os"

	"k8s.io/klog/v2"
)

// GetWithDefault returns the ENV variable named `key` or if not set a default value.
func GetWithDefault(key, defaultValue string) string {
	env, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}
	return env
}

// GetRequired returns the ENV variable named `key` or exits with an error message.
func GetRequired(key string) string {
	env, ok := os.LookupEnv(key)
	if !ok {
		klog.Fatalf("ENV variable $%s must be set\n", key)
	}
	return env
}
