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
			CAMountPath: "/etc/ssl/certs/injected-ca.pem",
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

//nolint:funlen // want to test in sequence
func TestMutatePods(t *testing.T) {
	podJSON, err := json.Marshal(testPod)
	require.NoError(t, err)

	fakeClient := fake.NewSimpleClientset()
	// fake client doesn't support "apply" patches, so adding separate logic
	var appliedConfigMap core.ConfigMap
	fakeClient.PrependReactor("patch", "configmaps",
		func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			err = json.Unmarshal(action.(clienttesting.PatchAction).GetPatch(), &appliedConfigMap)
			require.NoError(t, err)
			return true, nil, nil
		},
	)

	webhook := CAInjectionWebhook{
		CAInjectionWebhookConfig: CAInjectionWebhookConfig{
			CACert:      "test ca",
			CAMountPath: "/etc/ssl/certs/injected-ca.pem",
		},
		clientset: fakeClient,
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
							"configMap": {
								"name": "pod-ca-trust.crt"
							}
						}
					]
				}
			]`,
			string(response.Patch),
		)
		assert.Equal(t, "pod-ca-trust.crt", appliedConfigMap.Name)
		assert.Equal(t, "default", appliedConfigMap.Namespace)
		assert.Equal(t, map[string]string{
			"ca.crt": webhook.CACert,
		}, appliedConfigMap.Data)
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
		webhook.CAMountPath = "/etc/ssl/certs/my-ca.pem"
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
		assert.Equal(t, "pod-ca-trust.crt", appliedConfigMap.Name)
		assert.Equal(t, "default", appliedConfigMap.Namespace)
		assert.Equal(t, map[string]string{
			"ca.crt": webhook.CACert,
		}, appliedConfigMap.Data)
	})
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
