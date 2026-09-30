package containers

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
)

func TestLateEventContainerOutlivesProcessExit(t *testing.T) {
	r := &Registry{}
	c := &Container{}
	if r.lateEventContainer(42) != nil {
		t.Fatal("unknown pid must not resolve")
	}
	r.rememberExited(42, c)
	if r.lateEventContainer(42) != c {
		t.Fatal("events queued behind the exit event must still resolve to the container")
	}
	r.recentlyExited[42] = recentlyExitedProc{c: c, at: time.Now().Add(-2 * RecentlyExitedTTL)}
	if r.lateEventContainer(42) != nil {
		t.Fatal("entry must expire after RecentlyExitedTTL")
	}
	if _, ok := r.recentlyExited[42]; ok {
		t.Fatal("expired entry must be dropped")
	}
}

func TestEarlyCgroupResolvesContainerOfDeadProcess(t *testing.T) {
	r := &Registry{earlyCg: map[uint32]earlyCgroup{}, containersByCgroupId: map[string]*Container{}}
	c := &Container{}
	r.containersByCgroupId["/docker/abc"] = c
	if r.earlyContainer(7) != nil {
		t.Fatal("pid never seen must not resolve")
	}
	r.earlyCg[7] = earlyCgroup{cg: &cgroup.Cgroup{Id: "/docker/abc"}, at: time.Now()}
	if r.earlyContainer(7) != c {
		t.Fatal("cgroup read while the process was alive must resolve its container")
	}
	r.earlyCg[7] = earlyCgroup{cg: &cgroup.Cgroup{Id: "/docker/abc"}, at: time.Now().Add(-2 * RecentlyExitedTTL)}
	if r.earlyContainer(7) != nil {
		t.Fatal("stale entry must not resolve")
	}
}
