package common

import (
	"regexp"
	"strings"
)

var (
	deploymentPodRegex  = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[0-9a-f]{1,10}-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	daemonsetPodRegex   = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-[bcdfghjklmnpqrstvwxz2456789]{5}/.+`)
	statefulsetPodRegex = regexp.MustCompile(`(/k8s/[a-z0-9-]+/[a-z0-9-]+)-\d+/.+`)
	cronjobPodRegex     = regexp.MustCompile(`(/k8s-cronjob/[a-z0-9-]+/[a-z0-9-]+)/.+`)
)

func ContainerIdToOtelServiceName(containerId string) string {
	if !strings.HasPrefix(containerId, "/k8s/") {
		return containerId
	}
	for _, r := range []*regexp.Regexp{deploymentPodRegex, daemonsetPodRegex, statefulsetPodRegex, cronjobPodRegex} {
		if g := r.FindStringSubmatch(containerId); len(g) == 2 {
			return g[1]
		}
	}
	return containerId
}

// KubernetesContainer is a container of a Kubernetes pod, as the agent's
// container id names it: /k8s/<namespace>/<pod>/<container>, or
// /k8s-cronjob/<namespace>/<cron job>/<container> for the pod of a cron job.
type KubernetesContainer struct {
	Namespace string
	Pod       string
	CronJob   string
	Container string
}

// KubernetesContainerOf parses a container id; false when it is not the id of
// a container of a Kubernetes pod.
func KubernetesContainerOf(containerId string) (KubernetesContainer, bool) {
	kind, rest, found := strings.Cut(strings.TrimPrefix(containerId, "/"), "/")
	if !found {
		return KubernetesContainer{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return KubernetesContainer{}, false
	}
	switch kind {
	case "k8s":
		return KubernetesContainer{Namespace: parts[0], Pod: parts[1], Container: parts[2]}, true
	case "k8s-cronjob":
		return KubernetesContainer{Namespace: parts[0], CronJob: parts[1], Container: parts[2]}, true
	}
	return KubernetesContainer{}, false
}
