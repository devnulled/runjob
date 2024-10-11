# RunJob

## What

The RunJob project enables users to securely execute arbitrary commands on a remote Linux server using a CLI. This project utilizes [Linux Control Group v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html) to isolate the environment and resources of each command.

This document will refer to these arbitrary commands as [Jobs](##jobs).

## Why

This project aims to secure the execution of arbitrary commands on a remote Linux system using a simple client/server model. This functionality provides a good proof of concept for learning about using group v2 and an example of how one works.

It will utilize the group v2 functionality in the Linux kernel to prevent resource contention between processes and securely isolate requested processes for multiple users.


## Details

The work to implement the RunJob product is broken up into three different areas of functionality:

1. [RunJob Library](#runjob-library)—General management of a Job on the server, such as starting/stopping a job, creating namespaces, and forwarding the output of a running job.
2. [RunJob Server](#runjob-server) - Provides a gRPC-based API and control plane for managing the state lifecycle of Jobs.  The server is also responsible for both the state and distribution of the streaming output from running jobs managed by the library
3. [RunJob CLI](#runjob-cli) - A command-line program that provides the ability to perform actions on a running server instance

### System Considerations and Scope

As this is more of a basic functional product rather than a full production-level application, here are some shortcuts being taken that will need to be expanded in the future:

- Assumes that the commands are meant to be simple one-off commands that use existing software installed on a target machine.
- Assumes that it's best not to enable networking by default but will allow the commands to piggy-back on the network access of parent processes if configured
- Assumes the target server is 64bit and has a kernel that supports cgroup v2
- Assumes the target server has enough resources to run processes, store output from jobs in memory, etc
- It does not make any guarantees about availability. Please see the [Future Enhancements](#future-enhancements) section for more details on some of the items needed that are beyond the scope of this project currently.
- No functionality for restarting failed jobs
- No implementation of pivot_root

### Jobs

Jobs are defined as an arbitrary process a user wants to run on a host server, which the host server executes and manages.

The library will abstract and implement all of the functionality for starting jobs and isolating them from other processes, detecting when they have completed or crashed, and stopping them.


### RunJob Library

The library provides functionality for running Jobs, and wrapping each running job with the following:

- Methods to start/stop/get status, and stream the output of a Job
- Isolating each Job using namespaces for PID, mount, and networking
- Managing each Jobs' resources: CPU, Memory, and Disk IO using cgroup v2
- Streams the output of a running job back to the server

The library will be built as an independent composition of functionality around managing processes that any other project could import and use. It will be designed to know nothing about the CLI or server. The server will use this library to manage running Jobs and distribute the output from running Jobs back to the CLI.

The library will use an external executable `jobrunner` as a child process to set up the namespaces and resource limits and execute the requested command in the Job. This is to circumvent issues around forking in Go.

The library will provide an example of integrating it into an executable binary called `jobrunner`, but will not rely on this binary itself.  For the implementation of this project, it will use the server binary `jobmanager` itself.  Something to the effect of:

`$ jobmanager runjob --command /bin/bash --args args`

After starting a Job, the library returns a `JobRunnerID`, which will be used only for internal tracking.

In the future library could be updated to use more cgroup v2 options such as reserving

### RunJob Server

The server will implement a gRPC API using the `JobManager` service in the `internal/proto/runjob_service.proto`

- Uses a signed CA Certificate bundle for Authentication and Authorization of users.
- Accepts authenticated and authorized requests to execute/view/stop jobs
- Allows only job owners to retrieve information about, or stop running jobs
- Distributes the output of Jobs concurrently to multiple clients
- Responsible for the state of which Jobs were requested by which user, and the Authentication & Authorization of who can access all of the Jobs and their respective outputs

In the future, this server could be updated to have more fine-grained specifications for running Jobs, offer a way for monitoring applications to inspect running processes, etc.

#### Server API

The API will be implemented in gRPC, communicate over mTLS 1.3, and require client and CA certificates. Each user of the service is required to have their own client certificate.

To avoid documentation drift, please reference this proto file for the most up-to-date and detailed API information:

`internal/proto/jobmanager_service.proto`

The API is subject to minor changes until the initial implementation is considered feature complete.

As a high-level overview, it will support the following requests in the initial version:

- Start - Run a new Job
- Stop - Stop an existing running Job
- Status - Retrieve the status of an existing job
- Stream - Stream the output back from a running job

Users can only perform operations on the Jobs they have started and have a valid JobID.

In a future version of the product, this could support a List method to list all running processes for a given user, all system processes for a monitoring/sysadmin type user, etc.

Also, a way to start a process but stay connected to the server and receive the streamed output instead of making a second call with the JobId to see the output.

#### RunJob Server UX

Available commands shown via running `$ jobmanager --help`:

```
$ jobmanager --help
Usage: jobmanager <command> [flags]

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  serve [flags]
    Start the gRPC Server

  runjob [flags]
    Execute a requested command in isolation; used by

Run "jobmanager <command> --help" for more information on a command.
```

Details about the serve command from `$ jobmanager serve --help`:

```
Usage: jobmanager serve [flags]

Start the gRPC Server

Flags:
  -h, --help                                  Show context-sensitive help.

  -H, --server-host="localhost:8443"          Host address of the RunJob server
      --cert-ca-path="certs/cert-ca.crt"      Path to CA cert file for authenticating server
      --tls-cert-path="certs/user-tls.crt"    Path to TLS user cert file
      --tls-key-path="certs/user-tls.key"     Path to TLS user key file
```

Starting up the server will look something like:

```
$ jobmanager serve
  --server-host="localhost:8443" \
  --cert-ca-path="certs/cert-ca.crt" \
  --tls-cert-path="certs/user-tls.crt" \
  --tls-key-path="certs/user-tls.key" \
  --server-command="/bin/bash" \
```

#### Server Job State Management

The server will implement a `JobManager`, which is responsible for managing and maintaining the state for each Job.

When a Job is created, the server generates a JobID, which users will use to track the job.  The JobId will be a UUID v4.

Each Job within the `JobManager` will have a buffer of its stored output and a mutex to allow safe reads/writes to its state.


### RunJob CLI

The CLI provides a simple interface that enables users to run requested processes on remote RunJob servers.  Each CLI request calls the RunJob server via gRPC (wrapped in mTLS 1.3) to make requests and accept responses.

A user can only perform actions on jobs that they created.

#### RunJob CLI UI

Available commands shown via running `$ runjob --help`:

```
$ runjob --help
Usage: runjob <command> [flags]

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  start <server-command> [flags]
    Start a Job on a remote server

  stop <job-id> [flags]
    Stop a Job on a remote server

  status <job-id> [flags]
    View the status of a Job on a remote server

  stream <job-id> [flags]
    Get the running output from a Job running on a remote server

Run "runjob <command> --help" for more information on a command.
```

Details about the start command from `$ runjob start --help`:

```
Usage: runjob start <server-command> [flags]

Start a Job on a remote server

Arguments:
  <server-command>    Full path of the command to run on the RunJob server

Flags:
  -h, --help                                  Show context-sensitive help.

  -H, --server-host="localhost:8443"          Host address of the RunJob server
      --cert-ca-path="certs/cert-ca.crt"      Path to CA cert file for authenticating server
      --tls-cert-path="certs/user-tls.crt"    Path to TLS user cert file
      --tls-key-path="certs/user-tls.key"     Path to TLS user key file
  -A, --command-args=COMMAND-ARGS,...         Arguments to the command being ran
```

Example of starting a job:

```
$ runjob start "/bin/bash" \
-A "echo hello world" \
--server-host="localhost:8443" \
--cert-ca-path="certs/cert-ca.crt" \
--tls-cert-path="certs/user-tls.crt" \
--tls-key-path="certs/user-tls.key" \
--server-command="/bin/bash" \
```


### Job Resource Limits

Resource limits will be set and hardcoded per job. To be explicit, these are limits rather than allocations.

These limits will be implemented in the library, using the Linux cgroup v2 functionality. The limits will be hardcoded for now in the first version.

There will not be any limits on the number of jobs a user can run, how many resources they use, etc.  Nor will there be any support for process monitoring or restarting.  At least some basic level of not allowing more than `n` processes per user seems like an important feature to implement in the next release.

### Job Isolation

The library will create the isolation before executing the Job.

Each Job will run in its own PID and mount namespace.  This ensures that it only has access to itself and its children and that other processes can't kill the processes in this namespace. Requested Jobs cannot see other PIDs or mounts running on the system.

By default, each Job also has its own network namespace to prevent sending or receiving traffic across the Internet or local network. This ensures that a user can only run a random process and cannot import from or export data to other network and Internet resources.

The functionality of network namespaces should be implemented further in a later version of the product to allow more flexibility, such as allowing a user to define which network interfaces should be in the container.

### Job Execution

The requested commands require the software to already be installed on the server. No functionality is built around installing new packages or performing a `docker pull`.

The library will utilize the server, `jobmanager serve` to call itself as a process wrapper.  This allows the process to create and mount a new proc filesystem before running the requsted command.  Without doing this, the process could end-up using the hosts proc filesystem.  This also follows a similar model as what Docker does when starting new processes with reexec.

For simplicity, the following terms will be used to describe each process of the process tree:

- `jobmanager` - The parent server process accepting gRPC connections being ran as `jobmanager serve`
- `runjob` - A child process of `jobmanager` which wraps the user command specified in the Job command by the user. It is invoked by calling `jobmanager runjob`
- command - A child process of `runjob`

This will be the approximate process for executing a Job in the `jobmanager` server:

- The library will call the `jobmanager` executable binary with an alternate mode called `runjob`, using `os/exec.Command()`. It will pass the Job command and command arguments as an argument.
- The library in the parent `jobmanager` process will also set `SysProcAttr.Pdeathsig = syscall.SIGKILL` on its `runjob` child process.  If the parent server process dies, the kernel will kill the child process and all of it's decendents as the parent process will have orphaned processes.
- As part of the `exec.Command()`, the library in the `runjob` child process will add process attributes via `syscall.SysProcAttr`for creating new namespaces for PID, mount, and network for the underlying `jobmanager runjob` process being created.
- The library in the `jobmanager runjob` child process will also use `syscall.SysProcAttr` attributes of `Setpgid: true` to create a new process group for the child process. This will allow the library to more easily manage any processes that this child process creates.
- The library in the `jobmanager runjob` child process will also set `SysProcAttr.Pdeathsig = syscall.SIGQUIT` so that if the parent process dies without cleaning-up any of its child processes, the kernel will send a `SIGQUIT` signal to the child processes so that they can exit gracefully.
- `jobmanager runjob` will utilize the library to duplicate `STDERR` to a new file descriptor using `FD_CLOEXEC`. This will cause `STDERR` to close once the Job command is executed.  Closing `STDERR` sets up the Job command to capture `STDOUT` and `STDERR` to the same stream.
- `jobmanager runjob` will utilize the library to mount a new proc filesystem, and then fork and execute the command and its arguments from the Job
- `jobmanager runjob` will duplicate `STDERR` to a new file descriptor using `FD_CLOEXEC` to close it once the Job command is executed.  This sets up the Job command to capture `STDOUT` and `STDERR` to the same stream, which is then streamed back to the parent process.
- If the process is launched successfully, the library will return an `io.ReadCloser` which can be read for the combined `STDOUT` and `STDERR` stream.

There might be some other related details to work through while implementing this functionality, but generally speaking, this will be the process for executing jobs.

### Job Output Streaming

The library will stream the combined output of `STDOUT` and `STDERR` of running processes in an `io.ReadCloser` back to the server. The library and server will be connected to the same pipe created before the `jobmanager runjob` is called to start the requested process.

The server will use a pub/sub model to distribute Jobs' output to clients. Each Job's output will be stored in its own associated buffer, which can then be replayed to one or many Subscribers (clients). The Jobs' buffer will support concurrent reads and writes via a mutex.  Subscribers can be created at any time and will be fed all of the contents in the buffer created since the start of the Job.

No durable storage of jobs or job messages is supported. If the RunJob server crashes or restarts, all output and state of running processes are lost.

### Job Shutdown

In Linux, a process group can be treated like one process for signaling.  Each process group has a process group ID (PGID).

Because the `command` process from `runjob` is getting its own PGID, we can send a signal to the process group so that it and its child processes can be shut down with one signal.  However, those child processes may have also created process groups.

When a `Stop` command is requested for a Job, here are the steps needed to shut down all related processes for a given Job:

- The `jobmanager` will call a mutex lock on the Job in the JobManager
- The `jobmanager` will send a `SIGQUIT` to the `runjob` associated with the Job.
- The `runjob` will get the PPID for it's child process via `syscall.Getpgid`, and send the `SIGQUIT` to that Process Group so that all of the child processes in the group will get the signal
- After 10 seconds, if the `runjob` child process hasn't exited, it will then send a `SIGKILL` to the process group and then exit its own process and close the `io.ReadCloser`
- Because of setting `SysProcAttr.Pdeathsig` when all of these associated processes were created, they should all get cleaned-up by the kernel if something happens like one of the child processes creating its own process group
- Once the `io.ReadCloser` closes, the `jobmanager` will call the library to clean-up the cgroup associated with the job
- The `jobmanager` will then release the mutex and mark the Job as competed

### Security

Plaintext connections will not be accepted.  Every connection to the service must use mTLS 1.3.

All requests will require trusted and signed certificates.

#### Authentication

The server will require the client to use a certificate signed by a trusted authority.

When the server is started, the trusted authorities will be configured by passing in a certificate bundle via the command line.

A certificate bundle contains PEM-encoded X.509 certificates.  Each certificate in the bundle is trusted to authenticate users.

[CRL](https://csrc.nist.gov/glossary/term/certificate_revocation_list) functionality will not be supported, but it would be an important feature to add in subsequent product versions.

To prevent clients from having access until the expiration of the CA, make the signatures of the client certificates time-limited.  This would limit the time a compromised client key could be used.

#### Service Authorization

A simple authorization scheme based on the client's certificate's Common Name (CN) will be used. Based on the CN, the client can only start/view/stop processes of that CN.


#### Transport Security

The implementation of mTLS will implement the recommendations of "[Mozilla Guideline v5.7, Go 1.14.4, modern configuration](https://ssl-config.mozilla.org/#server=go&version=1.14.4&config=modern&guideline=5.7)" but will be adapted to implement only the gRPC protocol.

The communication between the client and server is secured via mTLS 1.3, using the following cipher suites:

- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

These cipher suites [are not configurable in Go 1.23.2](https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/crypto/tls/common.go;drc=9eeb627f606e713854e117dd4e52af5bcad28b66;l=676). Mozilla recommends mTLS 1.3 without backward compatibility.


### Testing

Testing will be implemented pragmatically to test the most likely sources of bugs and ensure security rather than writing a full suite of unit tests for each component.  The following will be areas of focus:

- Testing for race conditions using the [Go Data Race Detector](https://go.dev/doc/articles/race_detector), deadlocks, ensuring reasonable timeouts, etc
- Process-related scenarios around processes being killed, not starting successfully, etc
- Communication between the library and server, and client and server
- Distribution of the JobMessages to one and multiple clients
- Security around CA certs, TLS, authentication, authorization, etc.


## References

- [Linux Control Group v2 Admin Guide](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [CMU Course on Namespaces and cgroup](https://www.andrew.cmu.edu/course/14-712-s20/applications/ln/Namespaces_Cgroups_Conatiners.pdf)
- [Containerd implementation of cgroups](https://github.com/containerd/cgroups)
- [golang.org/x/sys/unix](https://pkg.go.dev/golang.org/x/sys/unix)
- [Containers From Scratch](https://github.com/lizrice/containers-from-scratch)
- [NIST - Securing Web Transactions: TLS Server Certificate Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-16.pdf)
- [Mozilla TLS Recommednations](https://wiki.mozilla.org/Security/Server_Side_TLS)

## Future Enhancements

- Add tracing via OpenTelemetry
- Add server health/status/info API's
- Adding an auditable log for security purposes
- User resource limits (number of running jobs, CPU used, etc)
- Monitoring/retrying failed processes
- Implementing secure network support rather than just namespacing it to prevent all traffic
- Support dedicated resource allocations
- Support returning data from `memory.stat`, `io.stat`, [Pressure Stall Information](https://www.kernel.org/doc/html/latest/accounting/psi.html), etc
- Adding more granular control over IOPS
- SSO Integration + RBAC
- Fine-grained permissions for each action. For example, creating a monitoring role user that can't execute any processes but can see the status of all of them.
- Installing the server as a daemon so that it can get killed/restarted
- Based on customer/potential market demand, implement/refactor the product to meet additional security measures for compliance with various standards such as FIPS, PCI, FedRamp, etc.