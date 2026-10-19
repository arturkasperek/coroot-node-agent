package ebpftracer

// ParentPid returns the parent of a process, which the eBPF side records when
// the process starts (process_parents), so that it is known after the process
// is gone.
func (t *Tracer) ParentPid(pid uint32) (uint32, bool) {
	if t == nil || t.collection == nil {
		return 0, false
	}
	parents := t.collection.Maps["process_parents"]
	if parents == nil {
		return 0, false
	}
	var parent uint32
	if err := parents.Lookup(pid, &parent); err != nil {
		return 0, false
	}
	return parent, true
}
