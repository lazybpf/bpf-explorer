package discovery

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// agentLabelSelector matches the agent DaemonSet pods (see deploy/03-daemonset.yaml).
const agentLabelSelector = "app.kubernetes.io/name=bpf-explorer-agent"

// Kubernetes discovers agent pods via the in-cluster API. It lists on every
// call (v1); a SharedInformer is a documented follow-up.
type Kubernetes struct {
	client    kubernetes.Interface
	namespace string
	port      int
}

// NewKubernetes builds a discoverer using the pod's in-cluster ServiceAccount.
func NewKubernetes(namespace string, agentPort int) (*Kubernetes, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config (is the UI running in a pod?): %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Kubernetes{client: client, namespace: namespace, port: agentPort}, nil
}

// Endpoints lists Ready agent pods and returns one endpoint per node.
func (k *Kubernetes) Endpoints() ([]Endpoint, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pods, err := k.client.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: agentLabelSelector,
	})
	if err != nil {
		return nil, err
	}

	var eps []Endpoint
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.PodIP == "" || !podReady(pod) {
			continue
		}
		node := pod.Spec.NodeName
		if node == "" {
			node = pod.Name
		}
		eps = append(eps, Endpoint{
			Node: node,
			Addr: fmt.Sprintf("%s:%d", pod.Status.PodIP, k.port),
		})
	}
	return eps, nil
}

func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
