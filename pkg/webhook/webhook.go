package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/wI2L/jsondiff"
	admission "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	volumeName      = "injected-ca"
	volumeMountName = volumeName
	configMapName   = "pod-ca-trust.crt"
	configMapKey    = "ca.crt"
	verbosityDebug  = 2
)

type CAInjectionWebhookConfig struct {
	CACert      string
	CAMountPath string
}

type CAInjectionWebhook struct {
	CAInjectionWebhookConfig
	clientset kubernetes.Interface
}

var _ http.Handler = &CAInjectionWebhook{}

func New(config CAInjectionWebhookConfig) (*CAInjectionWebhook, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &CAInjectionWebhook{
		CAInjectionWebhookConfig: config,
		clientset:                clientset,
	}, nil
}

// ServeHTTP implements http.Handler
func (aw *CAInjectionWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request admission.AdmissionReview
	requestDecoder := json.NewDecoder(r.Body)
	err := requestDecoder.Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Request == nil {
		http.Error(w, "Missing request property", http.StatusBadRequest)
		return
	}

	var response admission.AdmissionReview
	response.SetGroupVersionKind(admission.SchemeGroupVersion.WithKind("AdmissionReview"))
	response.Response = aw.MutatePods(request.Request)
	response.Response.UID = request.Request.UID

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	responseEncoder := json.NewEncoder(w)
	_ = responseEncoder.Encode(response)
}

func (aw *CAInjectionWebhook) MutatePods(request *admission.AdmissionRequest) *admission.AdmissionResponse {
	if klog.V(verbosityDebug).Enabled() {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		_ = enc.Encode(request)
		klog.V(verbosityDebug).Infof("request: %s", buf.String())
	}

	// ignore requests with wrong type
	if request.Kind != meta.GroupVersionKind(core.SchemeGroupVersion.WithKind("Pod")) {
		return &admission.AdmissionResponse{
			Allowed:  true,
			Warnings: []string{"wrong object type sent to the webhook, ignored"},
		}
	}

	var pod core.Pod
	err := json.Unmarshal(request.Object.Raw, &pod)
	if err != nil {
		klog.Error(err)
		return &admission.AdmissionResponse{
			Allowed: false,
			Result: &meta.Status{
				Status:  meta.StatusFailure,
				Reason:  meta.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		}
	}

	podNameForLogs := pod.Name
	if podNameForLogs == "" {
		podNameForLogs = pod.GenerateName + "???"
	}

	if request.DryRun == nil || !*request.DryRun {
		klog.V(1).Infof("Applying CA cert ConfigMap in %q", request.Namespace)
		err := aw.applyCACertConfigmap(request.Namespace)
		if err != nil {
			return errorInternal(fmt.Errorf("applying CA ConfigMap: %w", err))
		}
	}

	mutatedPod := pod.DeepCopy()
	aw.applyVolume(mutatedPod)
	aw.applyVolumeMounts(mutatedPod)

	patch, err := jsondiff.Compare(pod, mutatedPod)
	if err != nil {
		return errorInternal(fmt.Errorf("generating patch: %w", err))
	}
	if patch == nil {
		klog.Infof(`Pod "%s/%s" unchanged.`, request.Namespace, podNameForLogs)
		return &admission.AdmissionResponse{Allowed: true}
	}
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return errorInternal(fmt.Errorf("serializing patch: %w", err))
	}
	patchType := admission.PatchTypeJSONPatch
	klog.Infof(`Pod "%s/%s" patched.`, request.Namespace, podNameForLogs)
	return &admission.AdmissionResponse{
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patchJSON,
	}
}

func (aw *CAInjectionWebhook) applyCACertConfigmap(namespace string) error {
	_, err := aw.clientset.CoreV1().ConfigMaps(namespace).Apply(context.Background(),
		v1.ConfigMap(configMapName, namespace).
			WithData(map[string]string{
				configMapKey: aw.CACert,
			}),
		meta.ApplyOptions{FieldManager: "pod-ca-trust-webhook"},
	)
	return err
}

func (aw *CAInjectionWebhook) applyVolume(pod *core.Pod) {
	caVolume := core.Volume{
		Name: volumeName,
		VolumeSource: core.VolumeSource{
			ConfigMap: &core.ConfigMapVolumeSource{
				LocalObjectReference: core.LocalObjectReference{
					Name: configMapName,
				},
			},
		},
	}

	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == volumeName {
			pod.Spec.Volumes[i] = caVolume
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, caVolume)
}

func (aw *CAInjectionWebhook) applyVolumeMounts(pod *core.Pod) {
	for i := range pod.Spec.Containers {
		aw.applyVolumeMount(&pod.Spec.Containers[i])
	}
	for i := range pod.Spec.InitContainers {
		aw.applyVolumeMount(&pod.Spec.InitContainers[i])
	}
}

func (aw *CAInjectionWebhook) applyVolumeMount(container *core.Container) {
	caVolumeMount := core.VolumeMount{
		Name:      volumeMountName,
		ReadOnly:  true,
		MountPath: aw.CAMountPath,
		SubPath:   configMapKey,
	}

	for i, mount := range container.VolumeMounts {
		if mount.Name == volumeMountName {
			container.VolumeMounts[i] = caVolumeMount
			return
		}
	}
	container.VolumeMounts = append(container.VolumeMounts, caVolumeMount)
}

func errorInternal(err error) *admission.AdmissionResponse {
	klog.Error(err)
	return &admission.AdmissionResponse{
		Allowed: false,
		Result: &meta.Status{
			Status:  meta.StatusFailure,
			Reason:  meta.StatusReasonInternalError,
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		},
	}
}
