package webhook

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/wI2L/jsondiff"
	admission "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	volumeName      = "injected-ca"
	volumeMountName = volumeName
)

type CAInjectionWebhook struct {
	CASecretName string
	CASecretKey  string
	CABundlePath string
}

var _ http.Handler = CAInjectionWebhook{}

// ServeHTTP implements http.Handler
func (aw CAInjectionWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (aw CAInjectionWebhook) MutatePods(request *admission.AdmissionRequest) *admission.AdmissionResponse {
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
		log.Printf("error: %v\n", err)
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

	podName := pod.Name
	if podName == "" {
		podName = pod.GenerateName + "???"
	}

	mutatedPod := pod.DeepCopy()
	aw.applyVolume(mutatedPod)
	aw.applyVolumeMounts(mutatedPod)

	patch, err := jsondiff.Compare(pod, mutatedPod)
	if err != nil {
		return errorInternal(err)
	}
	if patch == nil {
		log.Printf(`Pod "%s/%s" unchanged.`, pod.Namespace, podName)
		return &admission.AdmissionResponse{Allowed: true}
	}
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return errorInternal(err)
	}
	patchType := admission.PatchTypeJSONPatch
	log.Printf(`Pod "%s/%s" patched.`, pod.Namespace, podName)
	return &admission.AdmissionResponse{
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patchJSON,
	}
}

func (aw CAInjectionWebhook) applyVolume(pod *core.Pod) {
	optional := true
	caVolume := core.Volume{
		Name: volumeName,
		VolumeSource: core.VolumeSource{
			Secret: &core.SecretVolumeSource{
				SecretName: aw.CASecretName,
				Optional:   &optional,
			},
		},
	}

	for i, volume := range pod.Spec.Volumes {
		if volume.Name == volumeName {
			pod.Spec.Volumes[i] = caVolume
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, caVolume)
}

func (aw CAInjectionWebhook) applyVolumeMounts(pod *core.Pod) {
	for i := range pod.Spec.Containers {
		aw.applyVolumeMount(&pod.Spec.Containers[i])
	}
	for i := range pod.Spec.InitContainers {
		aw.applyVolumeMount(&pod.Spec.InitContainers[i])
	}
}

func (aw CAInjectionWebhook) applyVolumeMount(container *core.Container) {
	caVolumeMount := core.VolumeMount{
		Name:      volumeMountName,
		ReadOnly:  true,
		MountPath: aw.CABundlePath,
		SubPath:   aw.CASecretKey,
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
	log.Printf("error: %v\n", err)
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
