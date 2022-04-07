// Package main https://github.com/krallin/tini/blob/v0.19.0/src/tini.c 的 Go 语言实现
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	getopt "github.com/pborman/getopt/v2"
	"golang.org/x/sys/unix"
)

const (
	tiniVersion = "0.19.0"
	statusMax   = 255
	statusMin   = 0

	subreaperEnvVar             = "TINI_SUBREAPER"
	verbosityEnvVar             = "TINI_VERBOSITY"
	killProcessGroupGroupEnvVar = "TINI_KILL_PROCESS_GROUP"

	bootstrapProcessArg = "tini-go-bootstrap"
)

var (
	signalNames = map[string]syscall.Signal{
		"SIGHUP":    syscall.SIGHUP,
		"SIGINT":    syscall.SIGINT,
		"SIGQUIT":   syscall.SIGQUIT,
		"SIGILL":    syscall.SIGILL,
		"SIGTRAP":   syscall.SIGTRAP,
		"SIGABRT":   syscall.SIGABRT,
		"SIGBUS":    syscall.SIGBUS,
		"SIGFPE":    syscall.SIGFPE,
		"SIGKILL":   syscall.SIGKILL,
		"SIGUSR1":   syscall.SIGUSR1,
		"SIGSEGV":   syscall.SIGSEGV,
		"SIGUSR2":   syscall.SIGUSR2,
		"SIGPIPE":   syscall.SIGPIPE,
		"SIGALRM":   syscall.SIGALRM,
		"SIGTERM":   syscall.SIGTERM,
		"SIGCHLD":   syscall.SIGCHLD,
		"SIGCONT":   syscall.SIGCONT,
		"SIGSTOP":   syscall.SIGSTOP,
		"SIGTSTP":   syscall.SIGTSTP,
		"SIGTTIN":   syscall.SIGTTIN,
		"SIGTTOU":   syscall.SIGTTOU,
		"SIGURG":    syscall.SIGURG,
		"SIGXCPU":   syscall.SIGXCPU,
		"SIGXFSZ":   syscall.SIGXFSZ,
		"SIGVTALRM": syscall.SIGVTALRM,
		"SIGPROF":   syscall.SIGPROF,
		"SIGWINCH":  syscall.SIGWINCH,
		"SIGSYS":    syscall.SIGSYS,
	}
	notForwardSignals = map[syscall.Signal]struct{}{
		syscall.SIGFPE:  {},
		syscall.SIGILL:  {},
		syscall.SIGSEGV: {},
		syscall.SIGBUS:  {},
		syscall.SIGABRT: {},
		syscall.SIGTRAP: {},
		syscall.SIGSYS:  {},
		syscall.SIGTTIN: {},
		syscall.SIGTTOU: {},
		// Docker CLI 20.10.7 前有 bug 可能会发送这个信号，但是这个信号的默认是 Ign，基本上没有影响，不处理。
		// 参见：https://docs.docker.com/engine/release-notes/#20107
		// syscall.SIGURG: {},
	}
)

var (
	subreaper         = 0
	verbosity         = 1
	parentDeathSignal = syscall.Signal(0)
	warnOnReap        = 0
	killProcessGroup  = 0
	expectStatus      [(statusMax - statusMin + 1) / 32]int32
	signalChannel     = make(chan os.Signal, 1)
)

func expectStatusSet(i uint8)       { expectStatus[(i / 32)] |= (1 << (i % 32)) }
func expectStatusTest(i uint8) bool { return expectStatus[(i/32)]&(1<<(i%32)) != 0 }

func printLog(f *os.File, level string, format string, a ...interface{}) {
	fmt.Fprintf(f, "[%s tini-go (%d)] ", level, os.Getpid())
	fmt.Fprintf(f, format, a...)
	fmt.Fprintf(f, "\n")
}

func printFatal(format string, a ...interface{}) { printLog(os.Stderr, "FATAL", format, a...) }
func printWarning(format string, a ...interface{}) {
	if verbosity > 0 {
		printLog(os.Stderr, "WARNING", format, a...)
	}
}

func printInfo(format string, a ...interface{}) {
	if verbosity > 1 {
		printLog(os.Stdout, "INFO", format, a...)
	}
}

func printDebug(format string, a ...interface{}) {
	if verbosity > 2 {
		printLog(os.Stdout, "DEBUG", format, a...)
	}
}

func printTrace(format string, a ...interface{}) {
	if verbosity > 3 {
		printLog(os.Stdout, "TRACE", format, a...)
	}
}

func parseArgs() (exited bool, exitCode int, childArgs []string) {
	getopt.BoolLong("version", 0, "Show version and exit.")
	getopt.Bool('h', "Show this help message and exit.")
	getopt.Bool('s', "Register as a process subreaper (requires Linux >= 3.4).") // 注册当前进程为进程收割者，当子孙进程变为孤儿进程时其父进程变为当前进程，而不是 1 号进程
	pEnum := make([]string, 0, len(signalNames))
	for k := range signalNames {
		pEnum = append(pEnum, k)
	}
	p := getopt.Enum('p', pEnum, "", "Trigger SIGNAL when parent dies, e.g. \"-p SIGKILL\".") // 当父进程退出时，当前进程的接收的信号，默认为不会接收到信号
	getopt.Bool('v', "Generate more verbose output. Repeat up to 3 times.")                   // 输出更多的信息，最多 3 次
	getopt.Bool('w', "Print a warning when processes are getting reaped.")                    // 打印警告，当进程正在被收割时
	getopt.Bool('g', "Send signals to the child's process group.")                            // 发送信号给子进程的进程组
	e := new(uint8)
	getopt.Flag(e, 'e', "Remap EXIT_CODE (from 0 to 255) to 0") // 将子进程的 EXIT_CODE (从 0 到 255) 重映射为 0 （使用位图原因是可以传递多个）
	getopt.Bool('l', "Show license and exit.")                  // 显示许可证并退出

	printUsage := func(f *os.File) {
		fmt.Fprintf(f, "%s (tini-go version %s)\n", getopt.CommandLine.Program(), tiniVersion)
		fmt.Fprintf(f, "Usage: %s [OPTIONS] PROGRAM -- [ARGS] | --version\n\n", getopt.CommandLine.Program())
		fmt.Fprintf(f, "Execute a program under the supervision of a valid init process (%s)\n\n", getopt.CommandLine.Program())
		fmt.Fprint(f, "Command line options:\n\n")
		getopt.CommandLine.PrintOptions(f)
		fmt.Fprint(f, "\nEnvironment variables:\n\n")
		fmt.Fprintln(f, "  TINI_SUBREAPER: Register as a process subreaper (requires Linux >= 3.4).")
		fmt.Fprintln(f, "  TINI_VERBOSITY: Set the verbosity level (default: 1).")
		fmt.Fprintln(f, "  TINI_KILL_PROCESS_GROUP: Send signals to the child's process group.")
		fmt.Fprintln(f)
	}

	err := getopt.Getopt(func(o getopt.Option) bool {
		if o.LongName() == "version" {
			fmt.Printf("%s\n", tiniVersion)
			exited = true
			exitCode = 0
			return false
		}
		switch o.ShortName() {
		case "h":
			printUsage(os.Stdout)
			exited = true
			exitCode = 0
			return false
		case "s":
			subreaper++
		case "p":
			parentDeathSignal = signalNames[*p]
		case "v":
			verbosity++
		case "w":
			warnOnReap++
		case "g":
			killProcessGroup++
			break
		case "e":
			expectStatusSet(*e)
		case "l":
			fmt.Print(LICENSE)
			exited = true
			exitCode = 0
			return false
		default:
			/* Should never happen */
			/* 应该不会发生 */
			exited = true
			exitCode = 1
			return false
		}
		return true
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err.Error())
		printUsage(os.Stderr)
		exited = true
		exitCode = 1
	}
	if exited {
		return
	}
	if getopt.NArgs() == 0 {
		/* User forgot to provide args! */
		printUsage(os.Stderr)
		exited = true
		exitCode = 1
		return
	}
	childArgs = getopt.Args()
	return
}

func parseEnv() (exited bool) {
	if os.Getenv(subreaperEnvVar) != "" {
		subreaper++
	}

	if os.Getenv(killProcessGroupGroupEnvVar) != "" {
		killProcessGroup++
	}

	envVerbosity := os.Getenv(verbosityEnvVar)
	if envVerbosity != "" {
		verbosity, _ = strconv.Atoi(envVerbosity)
	}

	return false
}

func configureSignals() error {
	// 这里和 c 语言班 tini 实现不一样，原因是 Go 语言无法修改信号屏蔽字。
	//
	// Go 的 Ignore 同样会被子进程继承的
	// 参见 https://github.com/golang/go/issues/20479
	signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)

	for i := 1; i <= 64; i++ {
		// signal.Ignored 必须的，防止转发某些被忽略的信号，如 docker 场景的 SIGURG。
		if _, ok := notForwardSignals[syscall.Signal(i)]; !ok {
			signal.Notify(signalChannel, syscall.Signal(i))
		}
	}
	return nil
}

func registerSubreaper() (exited bool) {
	if subreaper > 0 {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(1), 0, 0, 0); err != nil {
			errno := err.(syscall.Errno)
			if errno == syscall.EINVAL {
				printFatal("PR_SET_CHILD_SUBREAPER is unavailable on this platform. Are you using Linux >= 3.4?")
			} else {
				printFatal("Failed to register as child subreaper: %s", errno.Error())
			}
			return true
		} else {
			printTrace("Registered as child subreaper")
		}
	}
	return false
}

func reaperCheck() {
	/* Check that we can properly reap zombies */
	/* 检查是否可以正确回收僵尸进程 */
	var bit uintptr

	if os.Getpid() == 1 {
		return
	}

	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&bit)), 0, 0, 0); err != nil {
		printDebug("Failed to read child subreaper attribute: %s", err.Error())
	} else if bit == 1 {
		return
	}

	printWarning(`Tini is not running as PID 1 and isn't registered as a child subreaper.
Zombie processes will not be re-parented to Tini, so zombie reaping won't work.
To fix the problem, use the -s option or set the environment variable TINI_SUBREAPER to register Tini as a child subreaper, or run Tini as PID 1.`)
}

// tcsetpgrp sets the foreground process group ID associated with the
// terminal referred to by fd to pgrp.
//
// See POSIX.1 documentation for more details:
// https://pubs.opengroup.org/onlinepubs/9699919799/functions/tcsetpgrp.html
func tcsetpgrp(fd int, pgrp int) (err error) {
	return unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgrp)
}

func isolateChild() (exitCode int) {
	// Put the child into a new process group.
	// 将子进程放入新的进程组中，并作为组长进程。
	if err := syscall.Setpgid(0, 0); err != nil {
		printFatal("setpgid failed: %s", err.Error())
		return 1
	}

	// If there is a tty, allocate it to this new process group. We
	// can do this in the child process because we're **ignoring** (the word is **blocking** on https://github.com/krallin/tini/blob/v0.19.0/src/tini.c#L158)
	// SIGTTIN / SIGTTOU.

	// 如果存在控制终端，则将其分配给这个新的进程组。（通过 TcSetpgrp 函数）
	// 我们可以在作为后台进程的子进程这么做的原因是我们在前面已经忽略了 SIGTTIN / SIGTTOU 信号
	// （TcSetpgrp 函数在后台进程执行会触发 SIGTTIN / SIGTTOU 信号）

	// Doing it in the child process avoids a race condition scenario
	// if Tini is calling Tini (in which case the grandparent may make the
	// parent the foreground process group, and the actual child ends up...
	// in the background!)

	// 如果 Tini 正在调用 Tini，则在子进程中执行此操作可以避免出现争用情况
	// （在这种情况下，祖父母可能会将父进程设为前台进程组，而实际的子进程最终会在后台执行！）

	// https://man7.org/linux/man-pages/man3/tcgetpgrp.3.html
	if err := tcsetpgrp(syscall.Stdin, unix.Getpgrp()); err != nil {
		errno := err.(syscall.Errno)
		if errno == syscall.ENOTTY {
			printDebug("tcsetpgrp failed: no tty (ok to proceed)")
		} else if errno == syscall.ENXIO {
			// can occur on lx-branded zones
			printDebug("tcsetpgrp failed: no such device (ok to proceed)")
		} else {
			printFatal("tcsetpgrp failed: %s", errno.Error())
			return 1
		}
	}

	return 0
}

func restoreSignals() (exitCode bool) {
	// 从父进程中继承了这两个信号的 Ignore 行为，
	// 不恢复的话 signal.Ignore 在 exec 后仍然生效，exec 的执行环境就被污染了，
	// 参见： https://github.com/golang/go/issues/20479 。

	// 但是 Golang 有一个 bug 直接 reset 是不生效的，是一个 bug，
	// 原因参见： https://github.com/golang/go/issues/46321 。
	// 所以先 Notify 一下再恢复。
	signal.Notify(make(chan os.Signal), syscall.SIGTTOU, syscall.SIGTTIN)
	signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
	return false
}

func bootstrap(childArgs []string) (exitCode int) {
	// 子进程

	// Put the child in a process group and make it the foreground process if there is a tty.
	// 为子进程创建一个进程组，并作为组长进程，如果存在 tty，则将其设置为前台进程。
	if exitCode = isolateChild(); exitCode != 0 {
		return
	}

	// Restore all signal handlers to the way they were before we touched them.
	// 将所有信号处理程序恢复到我们触摸它们之前的状态。
	if restoreSignals() {
		exitCode = 1
		return
	}

	// 解析 Path
	childPath := childArgs[0]
	if filepath.Base(childPath) == childPath {
		if lp, err := exec.LookPath(childPath); err != nil {
			printFatal("%s", err.Error())
			exitCode = 127
			return
		} else {
			childPath = lp
		}
	}
	// 执行命令
	// childArgs[0] = childPath
	err := syscall.Exec(childPath, childArgs, os.Environ())

	// execvp will only return on an error so make sure that we check the errno
	// and exit with the correct return status for the error that we encountered
	// See: http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF

	// execvp 只会在错误时返回，因此请确保我们检查 errno 并以正确的返回状态退出我们遇到的错误
	// 参见：http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
	exitCode = 1
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.ENOENT:
			exitCode = 127
		case syscall.EACCES:
			exitCode = 126
			break
		}
		printFatal("exec %s failed: %s", childArgs[0], errno.Error())
		return
	}
	return
}

func spawn(childArgs []string) (exitCode int, childPid int) {
	// 注意不能使用 syscall.SYS_FORK，原因是 go 是多线程的， fork 在多线程场景是问题。
	// // https://stackoverflow.com/questions/16977988/details-of-syscall-rawsyscall-syscall-syscall-in-go
	// // https://www.cnblogs.com/dream397/p/14301620.html
	// // 使用 Syscall 而不是 RawSyscall。
	// pid, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)

	// TODO: check if tini was a foreground process to begin with (it's not OK to "steal" the foreground!")

	// 不使用 exec.Cmd 通过 Foreground 直接启动的原因是，tini C 版本要求没有控制终端也可以正常运行

	// 采用 docker 的方案，调用自身的子命令的方式。
	// https://github.com/moby/moby/blob/master/pkg/reexec/command_linux.go
	// 构造参数
	myChildArgs := []string{bootstrapProcessArg}
	// 构造 -v 参数
	vFlag := "-"
	for i := 1; i < verbosity; i++ {
		vFlag += "v"
	}
	if vFlag != "-" {
		myChildArgs = append(myChildArgs, vFlag)
	}
	// 使用 -- 分割真正的参数
	myChildArgs = append(myChildArgs, "--")
	myChildArgs = append(myChildArgs, childArgs...)
	cmd := &exec.Cmd{
		Path:   "/proc/self/exe", // 先只支持 Linux
		Args:   myChildArgs,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	// 子进程的处理函数在 bootstrap 函数
	err := cmd.Start()
	if err != nil {
		printFatal("fork failed: %s", err.Error())
		exitCode = 1
		return
	}
	childPid = int(cmd.Process.Pid)
	printInfo("Spawned child process '%s' with pid '%d'", childArgs[0], childPid)
	return
}

func waitAndForwardSignal(childPid int) {
	for {
		sig := <-signalChannel
		switch sig {
		// 子进程退出时，将收到该信号
		case syscall.SIGCHLD:
			/* Special-cased, as we don't forward SIGCHLD. Instead, we'll
			 * fallthrough to reaping processes.
			 */
			/*特殊处理，不转发 SIGCHLD 信号，而是由 reapZombies 处理。*/
			printDebug("Received SIGCHLD")
		default:
			printDebug("Passing signal: '%s'", sig.String())
			/* Forward anything else */
			/* 否则转发信子进程组 */
			killTarget := childPid
			if killProcessGroup > 0 {
				killTarget = -killTarget
			}
			if err := syscall.Kill(killTarget, sig.(syscall.Signal)); err != nil {
				errno := err.(syscall.Errno)
				if errno == syscall.ESRCH {
					printWarning("Child was dead when forwarding signal")
				} else {
					printFatal("Unexpected error when forwarding signal: '%s'", errno.Error())
					os.Exit(1)
				}
			}
		}
	}
}

func reapZombies(childPid int) (childExitCode int) {
	childExitCode = -1
	for {
		wstatus := syscall.WaitStatus(0)
		currentChildPid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
		if err != nil {
			// 报错
			errno := err.(syscall.Errno)
			if errno == syscall.ECHILD {
				printTrace("No child to wait")
				// 如果主子进程已经退出了，则直接返回
				if childExitCode != -1 {
					return
				}
			}
			childExitCode = -1
			printFatal("Error while waiting for pids: '%s'", errno.Error())
			return
		} else if currentChildPid == 0 {
			// 没有收到任何子进程
			printTrace("No child to reap")
			// 如果主子进程已经退出了，则直接返回
			if childExitCode != -1 {
				return
			}
			// 等待 1 秒后继续等待
			time.Sleep(1 * time.Second)
		} else {
			/* A child was reaped. Check whether it's the main one. If it is, then
			* set the exit_code, which will cause us to exit once we've reaped everyone else.
			 */
			/* 收到一个孩子进程。检查该进程是否是主子进程。如果是，
			* 则该设置 exitCode，直到没有收到任何子进程后，当前进程退出。
			 */
			printDebug("Reaped child with pid: '%d'", currentChildPid)
			if currentChildPid == childPid {
				// 参考 glibc WIFEXITED
				if wstatus&0x7f == 0 {
					/* Our process exited normally. */
					/* 主子进程正常退出. */
					printInfo("Main child exited normally (with status '%d')", wstatus.ExitStatus())
					childExitCode = wstatus.ExitStatus()
				} else if wstatus.Signaled() {
					/* Our process was terminated. Emulate what sh / bash
					* would do, which is to return 128 + signal number.
					 */
					/* 主进程进程终止。模拟 sh / bash 的行为，
					* 即返回 128 + 信号编号
					 */
					printInfo("Main child exited with signal (with signal '%s')", wstatus.Signal().String())
					childExitCode = 128 + int(wstatus.Signal())
				} else {
					// 未知原因主子进程退出了
					printFatal("Main child exited for unknown reason")
					return
				}

				// Be safe, ensure the status code is indeed between 0 and 255.
				// 安全起见，确保退出码范围在 0 和 255 之间。
				childExitCode = childExitCode % (statusMax - statusMin + 1)

				// If this exitcode was remapped, then set it to 0.
				// 如果此退出码被设置为重新映射，则将其设置为 0。
				if expectStatusTest(uint8(childExitCode)) {
					childExitCode = 0
				}
			} else if warnOnReap > 0 {
				printWarning("Reaped zombie process with pid=%d", currentChildPid)
			}

			// Check if other childs have been reaped.
			// 检查是否收获了其他孩子。
			continue
		}
	}
}

func main() {
	// Go 语言特殊逻辑，作为子进程的 bootstrap 启动
	// tini-go-bootstrap -vv -- ...
	// tini-go-bootstrap -- ...
	if len(os.Args) >= 3 && os.Args[0] == bootstrapProcessArg {
		realArgs := os.Args[2:]
		if os.Args[1] != "--" && os.Args[2] == "--" {
			realArgs = os.Args[3:]
			for _, c := range os.Args[1] {
				if c == 'v' {
					verbosity++
				}
			}
		}
		exitCode := bootstrap(realArgs)
		os.Exit(exitCode)
	}

	/* Parse command line arguments */
	/* 解析命令行参数 */
	exited, exitCode, childArgs := parseArgs()
	if exited {
		os.Exit(exitCode)
	}

	/* Parse environment */
	/* 解析环境变量 */
	if parseEnv() {
		os.Exit(1)
	}

	/* Configure signals */
	/* 配置信号 */
	configureSignals()

	/* Trigger signal on this process when the parent process exits. */
	/* 配置当前进程的父进程退出时，当前进程收到的信号 */
	// https://gist.github.com/corvuscrypto/cec8255687aa962c3562d0e5c548da37#file-main-go-L52
	if parentDeathSignal != 0 {
		if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(parentDeathSignal), 0, 0, 0); err != nil {
			printFatal("Failed to set up parent death signal")
			os.Exit(1)
		}
	}

	/* If available and requested, register as a subreaper */
	/* 如何内核支持且指定参数，配置当前进程为进程收割者 */
	if registerSubreaper() {
		os.Exit(1)
	}

	/* Are we going to reap zombies properly? If not, warn. */
	/* 当前进程是否可以正确地收获僵尸吗？如果否，请发出警告。*/
	reaperCheck()

	/* Go on */
	/* 开始执行 */
	spawnExitCode, childPid := spawn(childArgs)
	if spawnExitCode != 0 {
		os.Exit(spawnExitCode)
		return
	}

	// 处理信号
	go waitAndForwardSignal(childPid)
	/* Now, reap zombies */
	/* 现在，收割僵尸进程 */
	childExitCode := reapZombies(childPid)
	if childExitCode == -1 {
		os.Exit(1)
	} else {
		printTrace("Exiting: child has exited")
		os.Exit(childExitCode)
	}
}
