// hunt_exercise produces one local-only, EDR-only manual investigation exercise.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("hunt_exercise", flag.ContinueOnError)
	flags.SetOutput(output)
	seed := flags.String("seed", "", "required unsigned integer")
	start := flags.String("start", "", "required UTC timestamp, YYYY-MM-DDTHH:MM:SSZ")
	runID := flags.String("run-id", "", "required 1-8 uppercase letters/digits; use a fresh ID")
	out := flags.String("out", "", "required NEW output directory (never overwritten)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *seed == "" || *out == "" || flags.NArg() != 0 {
		return fmt.Errorf("--seed, --start, --run-id and --out are required; no positional arguments")
	}
	n, err := strconv.ParseUint(*seed, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid seed: %w", err)
	}
	bundle, err := generate(Inputs{Seed: n, Start: *start, RunID: *runID})
	if err != nil {
		return err
	}
	files, err := renderFiles(bundle)
	if err != nil {
		return err
	}
	// Refuse existing directories, including partially generated runs. No overwrite,
	// deletion, network client, environment credentials, or ingestion option exists.
	if err := os.Mkdir(*out, 0755); err != nil {
		return fmt.Errorf("create NEW output directory: %w", err)
	}
	for name, body := range files {
		path := filepath.Join(*out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(path, body, 0644); err != nil {
			return err
		}
	}
	fmt.Fprintf(output, "Generated %d synthetic EDR records in %s. Nothing ingested. Start with PREPARE.md, then ANALYST-BRIEF.md.\n", len(bundle.Events), *out)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
