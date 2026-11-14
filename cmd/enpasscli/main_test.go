package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInterspersedFlags(t *testing.T) {
	for _, tc := range []struct {
		input, want []string
		fail        bool
	}{
		{[]string{"edit", "Example", "-notes", "new notes", "-force"}, []string{"-notes", "new notes", "-force", "--", "edit", "Example"}, false},
		{[]string{"-notes=-value", "edit", "Example"}, []string{"-notes=-value", "--", "edit", "Example"}, false},
		{[]string{"edit", "--", "-notes", "literal"}, []string{"--", "edit", "-notes", "literal"}, false},
		{[]string{"edit", "Example", "-unknown"}, nil, true},
		{[]string{"edit", "Example", "-notes"}, nil, true},
	} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.String("notes", "", "")
		fs.Bool("force", false, "")
		got, err := interspersedFlags(fs, tc.input)
		if (err != nil) != tc.fail || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: got %v, err %v", tc.input, got, err)
		}
	}
}

func TestCLIProcess(t *testing.T) {
	if os.Getenv("ENPASS_CLI_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"enpasscli"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("enpasscli", flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestCLIWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vault.enpassdb", "vault.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "test", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(input string, success bool, args ...string) string {
		t.Helper()
		argv := append([]string{"-test.run=^TestCLIProcess$", "--", "-vault", dir, "-nonInteractive"}, args...)
		c := exec.Command(os.Args[0], argv...)
		c.Env = append(os.Environ(), "ENPASS_CLI_TEST_PROCESS=1", "MASTERPW=absolutely-No-clue")
		c.Stdin = strings.NewReader(input)
		var out, stderr bytes.Buffer
		c.Stdout = &out
		c.Stderr = &stderr
		err := c.Run()
		if (err == nil) != success {
			t.Fatalf("unexpected command result: %v; %s", err, stderr.String())
		}
		return out.String()
	}
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	run(secret+"\n", true, "create", "-title", "CLI TOTP", "-totp-stdin")
	read := func() []entryView {
		t.Helper()
		out := run("", true, "show", "CLI TOTP", "-json", "-detailed")
		var entries []entryView
		if err := json.Unmarshal([]byte(out), &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries", len(entries))
		}
		return entries
	}
	entries := read()
	if len(entries[0].Fields) != 1 || entries[0].Fields[0].Value != secret || entries[0].Fields[0].TOTPCode == "" {
		t.Fatal("TOTP creation failed")
	}
	out := run("", true, "list", "CLI TOTP", "-json", "-detailed")
	if strings.Contains(out, secret) {
		t.Fatal("list disclosed TOTP secret")
	}
	run("", true, "edit", "CLI TOTP", "-notes", "updated notes")
	run("", false, "edit", "CLI TOTP", "-notes", "rollback", "-totp", "otpauth://hotp/x?secret="+secret, "-force")
	run("", true, "edit", "CLI TOTP", "-clear", "totp", "-force")
	// Empty TOTP no longer appears in show, but the entry can still be edited.
	run("", true, "edit", "CLI TOTP", "-totp", secret, "-force")
	if read()[0].Fields[0].Value != secret {
		t.Fatal("TOTP replacement failed")
	}
	run("", false, "edit", "CLI TOTP")
	run("", false, "edit", "CLI TOTP", "-totp", secret) // confirmation cannot silently succeed
	run("", false, "edit", "-notes", "must require a filter")
}

func TestEntryDataStdinLimitsAndConflicts(t *testing.T) {
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine = oldFlags; os.Args = oldArgs })
	for _, tc := range []struct {
		args  []string
		input string
		fail  bool
	}{
		{[]string{"create", "-password-stdin"}, "secret\n", false},
		{[]string{"create", "-password-stdin", "-password=x"}, "", true},
		{[]string{"create", "-password-stdin", "-totp-stdin"}, "", true},
		{[]string{"create", "-totp-stdin"}, "", true},
		{[]string{"create", "-totp-stdin"}, strings.Repeat("A", 65537), true},
	} {
		flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		os.Args = append([]string{"enpasscli"}, tc.args...)
		args := &Args{}
		args.parse()
		data, err := entryData(args, strings.NewReader(tc.input))
		if (err != nil) != tc.fail {
			t.Fatalf("unexpected stdin validation result: %v", err)
		}
		if !tc.fail && data.Password != "secret" {
			t.Fatal("stdin password changed")
		}
	}
}
