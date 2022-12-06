package webhook

import (
	"encoding/json"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admission "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestMutatePods_NotAPod(t *testing.T) {
	webhook := CAInjectionWebhook{
		CAInjectionWebhookConfig: CAInjectionWebhookConfig{
			CASecretName:      "ca-secret",
			CASecretNamespace: "test",
			CASecretKey:       "ca.crt",
			CABundlePath:      "/etc/ssl/certs/injected-ca.pem",
		},
		clientset: fake.NewSimpleClientset(),
	}

	request := &admission.AdmissionRequest{
		Name: "something-else",
		Kind: meta.GroupVersionKind{
			Version: "v1",
			Kind:    "ConfigMap",
		},
	}

	response := webhook.MutatePods(request)
	assert.True(t, response.Allowed)
	assert.Empty(t, response.Patch)
}

func TestMutatePods(t *testing.T) {
	podJSON, err := json.Marshal(testPod)
	require.NoError(t, err)

	fakeClient := fake.NewSimpleClientset()
	// fake client doesn't support "apply" patches, so adding separate logic
	var appliedSecret core.Secret
	fakeClient.PrependReactor("patch", "secrets",
		func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			err = json.Unmarshal(action.(clienttesting.PatchAction).GetPatch(), &appliedSecret)
			require.NoError(t, err)
			return true, nil, nil
		},
	)

	webhook := CAInjectionWebhook{
		CAInjectionWebhookConfig: CAInjectionWebhookConfig{
			CASecretName:      "ca-secret",
			CASecretNamespace: "test",
			CASecretKey:       "ca.crt",
			CABundlePath:      "/etc/ssl/certs/injected-ca.pem",
		},
		clientset: fakeClient,
		caCert:    []byte("test ca"),
	}
	request := &admission.AdmissionRequest{
		Name:      testPod.Name,
		Namespace: testPod.Namespace,
		Kind:      meta.GroupVersionKind(testPod.GroupVersionKind()),
		Object:    runtime.RawExtension{Raw: podJSON},
	}
	response := webhook.MutatePods(request)

	t.Run("new pod", func(t *testing.T) {
		assert.True(t, response.Allowed)
		assert.Nil(t, response.Result)
		patchType := admission.PatchTypeJSONPatch
		assert.Equal(t, &patchType, response.PatchType)
		assert.JSONEq(t,
			`[
				{
					"op": "add",
					"path": "/spec/containers/0/volumeMounts",
					"value": [
						{
							"mountPath": "/etc/ssl/certs/injected-ca.pem",
							"name": "injected-ca",
							"readOnly": true,
							"subPath": "ca.crt"
						}
					]
				},
				{
					"op": "add",
					"path": "/spec/initContainers/0/volumeMounts",
					"value": [
						{
							"mountPath": "/etc/ssl/certs/injected-ca.pem",
							"name": "injected-ca",
							"readOnly": true,
							"subPath": "ca.crt"
						}
					]
				},
				{
					"op": "add",
					"path": "/spec/volumes",
					"value": [
						{
							"name": "injected-ca",
							"secret": {
								"secretName": "ca-secret"
							}
						}
					]
				}
			]`,
			string(response.Patch),
		)
		assert.Equal(t, "ca-secret", appliedSecret.Name)
		assert.Equal(t, "default", appliedSecret.Namespace)
		assert.Equal(t, map[string][]byte{
			"ca.crt": webhook.caCert,
		}, appliedSecret.Data)
	})

	patch, err := jsonpatch.DecodePatch(response.Patch)
	require.NoError(t, err)
	mutatedPod, err := patch.Apply(podJSON)
	require.NoError(t, err)
	request.Object.Raw = mutatedPod

	t.Run("already mutated pod", func(t *testing.T) {
		response = webhook.MutatePods(request)
		assert.True(t, response.Allowed)
		assert.Nil(t, response.Patch)
	})

	t.Run("changed path", func(t *testing.T) {
		webhook := webhook
		webhook.CABundlePath = "/etc/ssl/certs/my-ca.pem"
		response = webhook.MutatePods(request)
		assert.True(t, response.Allowed)
		assert.JSONEq(t,
			`[
				{
					"op": "replace",
					"path": "/spec/containers/0/volumeMounts/0/mountPath",
					"value": "/etc/ssl/certs/my-ca.pem"
				},
				{
					"op": "replace", 
					"path": "/spec/initContainers/0/volumeMounts/0/mountPath",
					"value": "/etc/ssl/certs/my-ca.pem"
				}
			]`, string(response.Patch),
		)
		assert.Equal(t, "ca-secret", appliedSecret.Name)
		assert.Equal(t, "default", appliedSecret.Namespace)
		assert.Equal(t, map[string][]byte{
			"ca.crt": webhook.caCert,
		}, appliedSecret.Data)
	})

	t.Run("changed secret", func(t *testing.T) {
		webhook := webhook
		webhook.CASecretName = "a-different-secret"
		response = webhook.MutatePods(request)
		assert.True(t, response.Allowed)
		assert.JSONEq(t,
			`[
				{
					"op": "replace",
					"path": "/spec/volumes/0/secret/secretName",
					"value": "a-different-secret"
				}
			]`, string(response.Patch),
		)
		assert.Equal(t, "a-different-secret", appliedSecret.Name)
		assert.Equal(t, "default", appliedSecret.Namespace)
		assert.Equal(t, map[string][]byte{
			"ca.crt": webhook.caCert,
		}, appliedSecret.Data)
	})
}

func TestMutatePods_RestrictiveServiceAccount(t *testing.T) {
	testPod := testPod.DeepCopy()
	testPod.Spec.ServiceAccountName = "test-sa"
	podJSON, err := json.Marshal(testPod)
	require.NoError(t, err)

	serviceAccount := &core.ServiceAccount{
		ObjectMeta: meta.ObjectMeta{
			Name:      "test-sa",
			Namespace: testPod.Namespace,
		},
		Secrets: []core.ObjectReference{{Name: "some-secret"}},
	}
	fakeClient := fake.NewSimpleClientset(serviceAccount)
	// fake client doesn't support "apply" patches, so adding separate logic
	var appliedSecret core.Secret
	fakeClient.PrependReactor("patch", "secrets",
		func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			err = json.Unmarshal(action.(clienttesting.PatchAction).GetPatch(), &appliedSecret)
			require.NoError(t, err)
			return true, nil, nil
		},
	)

	webhook := CAInjectionWebhook{
		CAInjectionWebhookConfig: CAInjectionWebhookConfig{
			CASecretName:      "ca-secret",
			CASecretNamespace: "test",
			CASecretKey:       "ca.crt",
			CABundlePath:      "/etc/ssl/certs/injected-ca.pem",
		},
		clientset: fakeClient,
		caCert:    []byte("test ca"),
	}
	request := &admission.AdmissionRequest{
		Name:      testPod.Name,
		Namespace: testPod.Namespace,
		Kind:      meta.GroupVersionKind(testPod.GroupVersionKind()),
		Object:    runtime.RawExtension{Raw: podJSON},
	}
	response := webhook.MutatePods(request)

	assert.True(t, response.Allowed)
	assert.Nil(t, response.Result)
	assert.Empty(t, response.Patch)
}

var testPod = core.Pod{
	TypeMeta: meta.TypeMeta{
		APIVersion: "v1",
		Kind:       "Pod",
	},
	ObjectMeta: meta.ObjectMeta{
		Name:      "my-pod",
		Namespace: "default",
	},
	Spec: core.PodSpec{
		Containers: []core.Container{{
			Name:  "main",
			Image: "main:v1.2.3",
			Ports: []core.ContainerPort{{
				ContainerPort: 80,
			}},
		}},
		InitContainers: []core.Container{{
			Name:  "init",
			Image: "init:v1.2.3",
		}},
	},
}
