# pod-ca-trust

This is a Mutating Admission Webhook to add trusted CAs to all Pods in a cluster.

**Limitation**: In the current version this will work for all Go based executables. Other binaries might not pick up the additional certificate(s), depending on the Linux distribution the container image is based on.

**Current use case:** Trust certificates issued by the Let's Encrypt Staging Environment in Kommander E2E tests.

## Installation:
1. Create a `kustomization.yaml`
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - git@github.com:mesosphere/pod-ca-trust.git//deploy?ref=v0.2.0 # <-- set the version here

# configure the installation namespace
namespace: pod-ca-trust

configMapGenerator:
  - name: config
    behavior: merge
    literals:
      - |
        CA_CERT=-----BEGIN CERTIFICATE-----
        [...]
        -----END CERTIFICATE-----
      # ^ one or multiple concatenated CA certificates in PEM format
      - CA_MOUNT_PATH=/etc/ssl/certs/injected-ca.pem # <-- where to mount the CA, this is the default if not set
```
2. Install
```sh
kubectl apply -k kustomization.yaml
```
