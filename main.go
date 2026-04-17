// proc-trace-tls — capture plaintext TLS traffic via ftrace uprobes on OpenSSL/GnuTLS
//
// Attaches uprobes to SSL_read / SSL_write (and their _ex variants) in libssl.so
// using the kernel's ftrace uprobe interface (/sys/kernel/debug/tracing).
// No eBPF. No ptrace. No kernel modules. Just ftrace and /proc.
//
// Requires root or CAP_SYS_ADMIN + CAP_DAC_OVERRIDE (for debugfs).
//
// Usage: proc-trace-tls [-achqQsv] [-l LIB] [-o FILE] [-p PID[,PID,...]]
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// ─── Constants ────────────────────────────────────────────────────────────────

var version = "dev"

const (
	tracingBase  = "/sys/kernel/debug/tracing"
	uprobeEvents = tracingBase + "/uprobe_events"
	tracePipe    = tracingBase + "/trace_pipe"
	traceOn      = tracingBase + "/tracing_on"

	defaultLibSSL = "libssl.so"
)

// probeTargets are the symbols we uprobe in libssl.
// We capture the return value (uretprobe) for reads to get actual byte counts.
var probeTargets = []struct {
	symbol string
	isRet  bool
	dir    string // "read" or "write"
}{
	{"SSL_read", false, "read"},
	{"SSL_read", true, "read"},
	{"SSL_write", false, "write"},
	{"SSL_read_ex", false, "read"},
	{"SSL_write_ex", false, "write"},
}

// ─── Options ──────────────────────────────────────────────────────────────────

var (
	watchPIDs  []int
	libSSLPath string
	outFile    string
	colorForce bool
	colorMode  bool
	quietMode  bool
	showErrors bool = true
	sizeOnly   bool
	hexDump    bool
	verbose    bool
	out        io.Writer = os.Stdout
)

// ─── Output ───────────────────────────────────────────────────────────────────

var (
	mu sync.Mutex
)

func clr(code, s string) string {
	if !colorMode || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ─── libssl discovery ─────────────────────────────────────────────────────────

// findLibSSL searches common library paths for libssl.so.
func findLibSSL() (string, error) {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib64/libssl.so.3",
		"/lib64/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.1.1",
	}

	// Also search via /proc/*/maps if watching specific PIDs
	if len(watchPIDs) > 0 {
		for _, pid := range watchPIDs {
			path := fmt.Sprintf("/proc/%d/maps", pid)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(line, "libssl") {
					fields := strings.Fields(line)
					if len(fields) >= 6 {
						lib := fields[5]
						if _, err := os.Stat(lib); err == nil {
							return lib, nil
						}
					}
				}
			}
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("libssl.so not found in standard paths; use -l to specify")
}

// symbolOffset returns the file offset of sym in the ELF at libPath.
// We shell out to nm/objdump since we avoid heavy dependencies.
func symbolOffset(libPath, sym string) (uint64, error) {
	// Try /proc/*/maps + /proc/*/mem approach for already-loaded libs,
	// or just use nm to get the offset.
	data, err := runCmd("nm", "-D", "--defined-only", libPath)
	if err != nil {
		// fallback to objdump
		data, err = runCmd("objdump", "-T", libPath)
		if err != nil {
			return 0, fmt.Errorf("nm/objdump not available: %v", err)
		}
	}

	re := regexp.MustCompile(`(?m)^([0-9a-f]+)\s+\S+\s+\S+\s+` + regexp.QuoteMeta(sym) + `\b`)
	m := re.FindStringSubmatch(string(data))
	if m == nil {
		// also try without the type fields (nm -D format: addr type name)
		re2 := regexp.MustCompile(`(?m)^([0-9a-f]+)\s+\S\s+` + regexp.QuoteMeta(sym) + `$`)
		m = re2.FindStringSubmatch(string(data))
	}
	if m == nil {
		return 0, fmt.Errorf("symbol %s not found in %s", sym, libPath)
	}
	offset, err := strconv.ParseUint(m[1], 16, 64)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func runCmd(name string, args ...string) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	pid, err := syscall.ForkExec(mustLookPath(name), append([]string{name}, args...),
		&syscall.ProcAttr{
			Files: []uintptr{uintptr(os.Stdin.Fd()), w.Fd(), w.Fd()},
		})
	w.Close()
	if err != nil {
		return nil, fmt.Errorf("exec %s: %v", name, err)
	}

	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	var ws syscall.WaitStatus
	syscall.Wait4(pid, &ws, 0, nil)
	return buf, nil
}

func mustLookPath(name string) string {
	dirs := []string{"/usr/bin", "/bin", "/usr/local/bin", "/sbin", "/usr/sbin"}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/" + name // best guess
}

// ─── Uprobe management ────────────────────────────────────────────────────────

type probeEntry struct {
	name   string
	isRet  bool
	dir    string
	symbol string
}

var registeredProbes []probeEntry

func registerUprobes(libPath string) error {
	seen := map[string]bool{}

	for _, t := range probeTargets {
		offset, err := symbolOffset(libPath, t.symbol)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  skipping %s: %v\n", t.symbol, err)
			}
			continue
		}

		prefix := "p"
		if t.isRet {
			prefix = "r"
		}
		name := fmt.Sprintf("tls_%s_%s", t.dir, t.symbol)
		if t.isRet {
			name += "_ret"
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		line := fmt.Sprintf("%s:%s %s:0x%x", prefix, name, libPath, offset)
		if err := appendToFile(uprobeEvents, line); err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  uprobe %s: %v\n", name, err)
			}
			continue
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "  registered: %s @ 0x%x\n", name, offset)
		}

		// Enable the event
		enablePath := fmt.Sprintf("%s/events/uprobes/%s/enable", tracingBase, name)
		if err := os.WriteFile(enablePath, []byte("1"), 0); err != nil && verbose {
			fmt.Fprintf(os.Stderr, "  enable %s: %v\n", name, err)
		}

		registeredProbes = append(registeredProbes, probeEntry{name: name, isRet: t.isRet, dir: t.dir, symbol: t.symbol})
	}

	if len(registeredProbes) == 0 {
		return fmt.Errorf("no uprobes registered — is OpenSSL installed?")
	}
	return nil
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, content)
	return err
}

func cleanupUprobes() {
	for _, p := range registeredProbes {
		enablePath := fmt.Sprintf("%s/events/uprobes/%s/enable", tracingBase, p.name)
		os.WriteFile(enablePath, []byte("0"), 0)

		removeLine := fmt.Sprintf("-%s", p.name)
		appendToFile(uprobeEvents, removeLine)
	}
}

// ─── Trace event parsing ──────────────────────────────────────────────────────

// Example trace line:
// curl-12345 [003] d... 123.456789: tls_write_SSL_write: (0x7f1234567890)
var traceRe = regexp.MustCompile(`^\s*(\S+)-(\d+)\s+\[\d+\].*\s+([\d.]+):\s+(tls_\w+)`)

type tlsEvent struct {
	comm      string
	pid       int
	ts        float64
	probeName string
	dir       string
}

func parseLine(line string) (*tlsEvent, bool) {
	m := traceRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	pid, _ := strconv.Atoi(m[2])
	ts, _ := strconv.ParseFloat(m[3], 64)

	dir := "?"
	if strings.Contains(m[4], "_read") {
		dir = "read"
	} else if strings.Contains(m[4], "_write") {
		dir = "write"
	}

	return &tlsEvent{
		comm:      m[1],
		pid:       pid,
		ts:        ts,
		probeName: m[4],
		dir:       dir,
	}, true
}

func isWatched(pid int) bool {
	if len(watchPIDs) == 0 {
		return true
	}
	for _, w := range watchPIDs {
		if pid == w {
			return true
		}
	}
	return false
}

// ─── Per-process data extraction ─────────────────────────────────────────────

func procComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimRight(string(data), "\n")
}

func procCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return procComm(pid)
	}
	// NUL-separated; take first two fields
	parts := strings.SplitN(strings.ReplaceAll(string(data), "\x00", " "), " ", 3)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return procComm(pid)
}

// ─── Event output ─────────────────────────────────────────────────────────────

var (
	lastPID int
	counter int64
)

func printEvent(ev *tlsEvent) {
	mu.Lock()
	defer mu.Unlock()

	counter++

	ts := time.Unix(0, int64(ev.ts*1e9)).Format("15:04:05.000")

	var dirStr, dirClr string
	if ev.dir == "write" {
		dirStr = "TX"
		dirClr = "33" // amber
	} else {
		dirStr = "RX"
		dirClr = "36" // cyan
	}

	pidStr := clr("33", strconv.Itoa(ev.pid))
	commStr := clr("96", ev.comm)
	dirFmt := clr(dirClr, dirStr)
	tsStr := clr("2", ts)

	sym := ev.probeName
	sym = strings.TrimPrefix(sym, "tls_read_")
	sym = strings.TrimPrefix(sym, "tls_write_")
	sym = strings.TrimSuffix(sym, "_ret")

	if sizeOnly {
		fmt.Fprintf(out, "%s %s %s %s %s\n",
			tsStr, pidStr, commStr, dirFmt, clr("2", sym))
		return
	}

	fmt.Fprintf(out, "%s %s %s %s %s\n",
		tsStr, pidStr, commStr, dirFmt, clr("2", sym))
}

// printable replaces non-printable bytes with '.'
func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 && unicode.IsPrint(rune(c)) {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			fatalf("unexpected argument: %s", a)
		}
		for _, ch := range a[1:] {
			switch ch {
			case 'a':
				// show all PIDs (default already)
			case 'c':
				colorForce = true
			case 'h':
				usage()
			case 'l':
				if i+1 >= len(args) {
					fatal("-l requires a path")
				}
				i++
				libSSLPath = args[i]
			case 'o':
				if i+1 >= len(args) {
					fatal("-o requires a path")
				}
				i++
				outFile = args[i]
			case 'p':
				if i+1 >= len(args) {
					fatal("-p requires a PID list")
				}
				i++
				for _, s := range strings.Split(args[i], ",") {
					s = strings.TrimSpace(s)
					if s == "" {
						continue
					}
					pid, err := strconv.Atoi(s)
					if err != nil || pid <= 0 {
						fatalf("-p: invalid PID: %s", s)
					}
					watchPIDs = append(watchPIDs, pid)
				}
			case 'q':
				quietMode = true
			case 'Q':
				showErrors = false
			case 's':
				sizeOnly = true
			case 'v':
				verbose = true
			case 'x':
				hexDump = true
			default:
				fatalf("unknown flag -%c", ch)
			}
		}
	}

	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fatalf("open %s: %v", outFile, err)
		}
		defer f.Close()
		out = f
	}

	if colorForce {
		colorMode = true
	} else if os.Getenv("NO_COLOR") == "" {
		if f, ok := out.(*os.File); ok {
			colorMode = isTerminal(f)
		}
	}

	// Find libssl
	if libSSLPath == "" {
		var err error
		libSSLPath, err = findLibSSL()
		if err != nil {
			fatalf("%v\nHint: install openssl or use -l /path/to/libssl.so", err)
		}
	}

	if !quietMode {
		fmt.Fprintf(os.Stderr, "%s\n", clr("96", "proc-trace-tls "+version))
		fmt.Fprintf(os.Stderr, "  lib : %s\n", clr("2", libSSLPath))
		if len(watchPIDs) > 0 {
			pidStrs := make([]string, len(watchPIDs))
			for i, p := range watchPIDs {
				pidStrs[i] = strconv.Itoa(p)
			}
			fmt.Fprintf(os.Stderr, "  pids: %s\n", clr("33", strings.Join(pidStrs, ",")))
		} else {
			fmt.Fprintf(os.Stderr, "  pids: %s\n", clr("2", "all"))
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Enable tracing
	if err := os.WriteFile(traceOn, []byte("1"), 0); err != nil {
		fatalf("enable tracing: %v\nAre you root? Is debugfs mounted at %s?", err, tracingBase)
	}

	// Register uprobes
	if verbose {
		fmt.Fprintf(os.Stderr, "Registering uprobes on %s...\n", libSSLPath)
	}
	if err := registerUprobes(libSSLPath); err != nil {
		fatalf("%v", err)
	}
	if !quietMode {
		fmt.Fprintf(os.Stderr, "Watching %d probe(s). Press Ctrl-C to stop.\n\n", len(registeredProbes))
	}

	// Cleanup on Ctrl-C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !quietMode {
			fmt.Fprintf(os.Stderr, "\n\ncaptured %d TLS events\n", counter)
		}
		cleanupUprobes()
		os.Exit(0)
	}()

	// Read trace_pipe
	f, err := os.Open(tracePipe)
	if err != nil {
		cleanupUprobes()
		fatalf("open trace_pipe: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ev, ok := parseLine(line)
		if !ok {
			continue
		}
		if !isWatched(ev.pid) {
			continue
		}
		printEvent(ev)
	}
}

// ─── Error helpers ────────────────────────────────────────────────────────────

func fatalf(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "proc-trace-tls: "+f+"\n", args...)
	os.Exit(1)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "proc-trace-tls: "+msg)
	os.Exit(1)
}

func usage() {
	const (
		bold    = "\033[1m"
		dim     = "\033[2m"
		reset   = "\033[0m"
		cyan    = "\033[36m"
		yellow  = "\033[33m"
		green   = "\033[32m"
		magenta = "\033[35m"
		purple  = "\033[35m"
	)
	e := os.Stderr
	fmt.Fprintf(e, "\n  %s🔒 proc-trace-tls%s %s%s%s — plaintext TLS traffic interceptor for Linux\n\n", bold+cyan, reset, dim, version, reset)
	fmt.Fprintf(e, "  %sUsage:%s\n", bold, reset)
	fmt.Fprintf(e, "    proc-trace-tls %s[flags]%s\n\n", dim, reset)
	fmt.Fprintf(e, "  %sFlags:%s\n", bold, reset)
	fmt.Fprintf(e, "    🎨  %s-c%s          colorize output %s(auto when stdout is a tty)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    🔗  %s-l%s %sLIB%s      path to libssl.so %s(auto-detected if omitted)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    📝  %s-o%s %sFILE%s     log output to FILE instead of stdout\n", yellow, reset, cyan, reset)
	fmt.Fprintf(e, "    🎯  %s-p%s %sPID%s      trace only PID(s) %s(comma-separated)%s\n", yellow, reset, cyan, reset, dim, reset)
	fmt.Fprintf(e, "    🤫  %s-q%s          suppress startup messages\n", yellow, reset)
	fmt.Fprintf(e, "    🔇  %s-Q%s          suppress error messages\n", yellow, reset)
	fmt.Fprintf(e, "    📊  %s-s%s          event summary only %s(no payload)%s\n", yellow, reset, dim, reset)
	fmt.Fprintf(e, "    🔍  %s-v%s          verbose probe registration\n", yellow, reset)
	fmt.Fprintf(e, "\n  %sExamples:%s\n", bold, reset)
	fmt.Fprintf(e, "    %s# watch all TLS traffic system-wide%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-tls\n\n")
	fmt.Fprintf(e, "    %s# trace a specific process%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-tls %s-p%s $(pgrep curl)\n\n", green, reset)
	fmt.Fprintf(e, "    %s# use a custom libssl path%s\n", dim, reset)
	fmt.Fprintf(e, "    sudo proc-trace-tls %s-l%s /usr/lib64/libssl.so.3\n\n", green, reset)
	os.Exit(1)
}
