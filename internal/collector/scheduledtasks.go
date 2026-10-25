package collector

import "context"

// scheduledTasksCollector reads the Task Scheduler job store
// (%SystemRoot%\System32\Tasks), one record per task: who it runs as, at what
// privilege, on which triggers, the program each action launches, and the
// task file's timestamps. It cross-checks the store against the Task
// Scheduler's registry cache (TaskCache\Tree) to find tasks hidden by
// deleting their security descriptor, tasks whose file was removed, and task
// files that were never registered.
type scheduledTasksCollector struct{ opts RunOptions }

func (*scheduledTasksCollector) Name() string        { return "scheduledtasks" }
func (*scheduledTasksCollector) Platforms() []string { return []string{"windows"} }

func (c *scheduledTasksCollector) Configure(o RunOptions) { c.opts = o }

func (c *scheduledTasksCollector) Collect(ctx context.Context) (Result, error) {
	return collectScheduledTasks(ctx, c.opts)
}

func init() { Register(&scheduledTasksCollector{}) }
