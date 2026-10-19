package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerIdToServiceName(t *testing.T) {
	f := ContainerIdToOtelServiceName
	assert.Equal(t,
		f("/k8s/otel-demo/otel-demo-frauddetectionservice-64cd4f9686-mvtnb/frauddetectionservice"),
		"/k8s/otel-demo/otel-demo-frauddetectionservice")

	assert.Equal(t,
		f("/k8s/coroot/coroot-node-agent-np9pk/node-agent"),
		"/k8s/coroot/coroot-node-agent")

	assert.Equal(t,
		f("/k8s/coroot/pyroscope-df884bb79-hhxtv/pyroscope"),
		"/k8s/coroot/pyroscope")

	assert.Equal(t,
		f("/k8s/default/cassandra-main-12/cassandra"),
		"/k8s/default/cassandra-main")

	assert.Equal(t,
		f("/k8s/default/hello-28283967-khz2f/xz"),
		"/k8s/default/hello")

	assert.Equal(t,
		f("/system.slice/k3s.service"),
		"/system.slice/k3s.service")

	assert.Equal(t,
		f("/docker/container_name"),
		"/docker/container_name")
}

func TestKubernetesContainerOfContainerId(t *testing.T) {
	container, ok := KubernetesContainerOf("/k8s/coroot-dev/demo-traffic-75b97975f8-4c8kf/traffic")
	assert.True(t, ok)
	assert.Equal(t, KubernetesContainer{Namespace: "coroot-dev", Pod: "demo-traffic-75b97975f8-4c8kf", Container: "traffic"}, container)

	// a cron job's id names the cron job, not the pod of the run
	container, ok = KubernetesContainerOf("/k8s-cronjob/default/hello/xz")
	assert.True(t, ok)
	assert.Equal(t, KubernetesContainer{Namespace: "default", CronJob: "hello", Container: "xz"}, container)

	for _, containerId := range []string{
		"/docker/a1b2c3",
		"/system.slice/k3s.service",
		"/k8s/coroot-dev/demo-traffic", // no container
		"/k8s//pod/container",
		"",
	} {
		_, ok = KubernetesContainerOf(containerId)
		assert.False(t, ok, containerId)
	}
}
