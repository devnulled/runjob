//go:build !linux

package job

// A bunch of stubbed out methods that don't do anything so that this
// can be built on platforms other than Linux

func StartLib() error {
	return nil
}

func (j *Job) StartJob() error {
	return nil
}

func (j *Job) StopJob() error {
	return nil
}

func StreamJob(j *Job) error {
	return nil
}

func JobStatus() *JobStatusReport {
	return NewDefaultJobStatus()
}

func (jcs *JobCommandSpec) StartProc() error {
	return nil
}

func StopLib() error {
	return nil
}
