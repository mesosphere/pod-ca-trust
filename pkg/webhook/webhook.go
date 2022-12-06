package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/wI2L/jsondiff"
	admission "k8s.io/api/admission/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	volumeName      = "injected-ca"
	volumeMountName = volumeName
)

type CAInjectionWebhookConfig struct {
	CASecretName      string
	CASecretNamespace string
	CASecretKey       string
	CABundlePath      string
}

type CAInjectionWebhook struct {
	CAInjectionWebhookConfig
	clientset kubernetes.Interface
	caCert    []byte
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

	caSecret, err := clientset.CoreV1().Secrets(config.CASecretNamespace).Get(context.Background(), config.CASecretName, meta.GetOptions{})
	if err != nil {
		return nil, err
	}

	log.Printf("CA: %s", caSecret.Data[config.CASecretKey])

	return &CAInjectionWebhook{
		CAInjectionWebhookConfig: config,
		clientset:                clientset,
		caCert:                   caSecret.Data[config.CASecretKey],
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

	podNameForLogs := pod.Name
	if podNameForLogs == "" {
		podNameForLogs = pod.GenerateName + "???"
	}

	if pod.Spec.ServiceAccountName != "" {
		sa, err := aw.clientset.CoreV1().ServiceAccounts(pod.Namespace).Get(context.Background(), pod.Spec.ServiceAccountName, meta.GetOptions{})
		if err != nil {
			return errorInternal(err)
		}
		if len(sa.Secrets) > 0 {
			return &admission.AdmissionResponse{
				Allowed:  true,
				Warnings: []string{fmt.Sprintf("pod %q uses a service account with restricted secrets, skipping", podNameForLogs)},
			}
		}
	}

	if request.DryRun == nil || !*request.DryRun {
		log.Println("applying secret in namespace", pod.Namespace)
		err := aw.applyCACertSecret(pod.Namespace)
		if err != nil {
			return errorInternal(err)
		}
	}

	mutatedPod := pod.DeepCopy()
	aw.applyVolume(mutatedPod)
	aw.applyVolumeMounts(mutatedPod)

	patch, err := jsondiff.Compare(pod, mutatedPod)
	if err != nil {
		return errorInternal(err)
	}
	if patch == nil {
		log.Printf(`Pod "%s/%s" unchanged.`, pod.Namespace, podNameForLogs)
		return &admission.AdmissionResponse{Allowed: true}
	}
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return errorInternal(err)
	}
	patchType := admission.PatchTypeJSONPatch
	log.Printf(`Pod "%s/%s" patched.`, pod.Namespace, podNameForLogs)
	return &admission.AdmissionResponse{
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patchJSON,
	}
}

func (aw *CAInjectionWebhook) applyCACertSecret(namespace string) error {
	_, err := aw.clientset.CoreV1().Secrets(namespace).Apply(context.Background(),
		v1.Secret(aw.CASecretName, namespace).
			WithData(map[string][]byte{
				aw.CASecretKey: aw.caCert,
			}),
		meta.ApplyOptions{FieldManager: "pod-ca-trust-webhook"},
	)
	return err
}

func (aw *CAInjectionWebhook) applyVolume(pod *core.Pod) {
	caVolume := core.Volume{
		Name: volumeName,
		VolumeSource: core.VolumeSource{
			Secret: &core.SecretVolumeSource{
				SecretName: aw.CASecretName,
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
