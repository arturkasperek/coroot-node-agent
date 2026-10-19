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

// A pid no process has any more (as high as pids go, so never a live one in
// the test): a process forked for one connection, gone before the agent read
// its /proc.
const goneChildPid = 4194000

// The process a server forks for one connection lives a few milliseconds:
// its /proc is gone when its events are handled, and so may be its cgroup read
// early. It belongs to the container of its parent, whose cgroup it inherited.
func TestGoneProcessBelongsToTheContainerOfItsParent(t *testing.T) {
	parent := &Container{}
	r := &Registry{
		containersByPid:        map[uint32]*Container{100: parent},
		containersByPidIgnored: map[uint32]*time.Time{},
		earlyCg:                map[uint32]earlyCgroup{},
		containersByCgroupId:   map[string]*Container{},
		parentPid: func(pid uint32) (uint32, bool) {
			return 100, pid == goneChildPid
		},
	}
	if r.getOrCreateContainer(goneChildPid) != parent {
		t.Fatal("a gone child must resolve to the container of its parent")
	}
	if r.lateEventContainer(goneChildPid) != parent {
		t.Fatal("its later events must resolve too, as those of an exited process")
	}
	if r.getOrCreateContainer(goneChildPid+1) != nil {
		t.Fatal("a gone pid with no known parent must not resolve")
	}
}
