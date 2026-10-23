// Interactive line-based prompting used by keygen (when the output path is
// not given) and by the setup wizard. Prompts and their accepted inputs are
// written to Out; input is read line by line from In.

package cli

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
)

// prompter asks questions and reads answers.
type prompter struct {
	In  *bufio.Reader
	Out io.Writer
}

// New builds a prompter reading from in and writing prompts to out.
func newPrompter(in io.Reader, out io.Writer) *prompter {
	return &prompter{In: bufio.NewReader(in), Out: out}
}

// Ask prints label with the default in brackets and returns the answer, or
// def on an empty line.
func (p *prompter) Ask(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.Out, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(p.Out, "%s: ", label)
	}
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	if line == "" {
		return def, nil
	}
	return line, nil
}

// Choose prints label with the accepted options and default, and repeats
// until the answer is one of the options (or empty, yielding def).
func (p *prompter) Choose(label string, options []string, def string) (string, error) {
	fmt.Fprintf(p.Out, "%s [%s] (%s): ", label, def, strings.Join(options, "/"))
	for {
		line, err := p.readLine()
		if err != nil {
			return "", err
		}
		if line == "" {
			return def, nil
		}
		if slices.Contains(options, line) {
			return line, nil
		}
		fmt.Fprintf(p.Out, "choose one of %s: ", strings.Join(options, "/"))
	}
}

// Confirm asks a yes/no question; empty accepts def.
func (p *prompter) Confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Fprintf(p.Out, "%s [%s]: ", label, hint)
	for {
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(line) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintf(p.Out, "answer y or n [%s]: ", hint)
	}
}

func (p *prompter) readLine() (string, error) {
	line, err := p.In.ReadString('\n')
	if err != nil {
		if line == "" {
			return "", fmt.Errorf("input ended before an answer was given")
		}
		// Last line without trailing newline is still an answer.
		line = strings.TrimRight(line, "\r\n")
		return line, nil
	}
	return strings.TrimRight(line, "\r\n"), nil
}
