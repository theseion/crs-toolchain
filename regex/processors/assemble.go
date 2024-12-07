// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/itchyny/rassemble-go"

	"github.com/coreruleset/crs-toolchain/v2/regex"
)

const (
	AssembleInput  string = `^\s*##!=<\s*(.*)$`
	AssembleOutput string = `^\s*##!=>\s*(.*)$`
)

type Assemble struct {
	proc   *Processor
	output strings.Builder
}

// NewAssemble creates a new assemble processor
func NewAssemble(ctx *Context) *Assemble {
	return &Assemble{
		proc: NewProcessor(ctx),
	}
}

// ProcessLine applies the processors logic to a single line
func (a *Assemble) ProcessLine(line string) error {
	match := regex.AssembleInputRegex.FindStringSubmatch(line)
	if len(match) > 0 {
		if err := a.store(match[1]); err != nil {
			logger.Error().Err(err).Msgf("Failed to store input: %s", line)
			return err
		}
		return nil
	}

	match = regex.AssembleOutputRegex.FindStringSubmatch(line)
	if len(match) > 0 {
		identifier := match[1]
		if err := a.append(identifier); err != nil {
			var message string
			if identifier != "" {
				message = fmt.Sprintf("Failed to append output with name %s", identifier)
			} else {
				message = "Failed to append output of previous block"
			}
			logger.Error().Err(err).Msg(message)
			return err
		}
	} else {
		a.proc.lines = append(a.proc.lines, line)
	}
	return nil
}

// Complete finalizes the processor, producing its output
func (a *Assemble) Complete() ([]string, error) {
	logger.Trace().Msg("Completing assembly")
	regex, err := a.runAssemble()
	if err != nil {
		return nil, err
	}

	result := a.wrapCompletedAssembly(regex)
	logger.Trace().Msgf("Completed assembly: %s", result)

	if result == "" {
		return []string{}, nil
	}

	return []string{result}, nil
}

// Consume applies the state of a nested processor
func (a *Assemble) Consume(lines []string) error {
	for _, line := range lines {
		if err := a.ProcessLine(line); err != nil {
			return err
		}
	}
	return nil
}

func (a *Assemble) store(identifier string) error {
	if len(identifier) == 0 {
		return errors.New("missing identifier for input marker")
	}

	if err := a.append(""); err != nil {
		return err
	}

	outputString := a.output.String()
	// reset output, the next call to `Complete` should not print
	// the value we just stored
	a.output.Reset()

	logger.Debug().Msgf("Storing expression at %s: %s", identifier, outputString)
	a.proc.ctx.stash[identifier] = outputString
	return nil
}

func (a *Assemble) append(identifier string) error {
	if len(identifier) == 0 {
		if len(a.proc.lines) == 1 {
			// Treat as literal, could be start of a group or a range expresssion.
			// Those can not be parsed by rassemble-go, since they are not valid
			// expressions.
			a.output.WriteString(a.proc.lines[0])
			a.proc.lines = []string{}
		}
		regex, err := a.runAssemble()
		if err != nil {
			return err
		}
		_, err = a.output.WriteString(regex)
		if err != nil {
			return err
		}
	} else {
		// Append lines that aren't yet in the output
		err := a.append("")
		if err != nil {
			return err
		}

		stored, ok := a.proc.ctx.stash[identifier]
		if !ok {
			return fmt.Errorf("no entry in the stash for name '%s'", identifier)
		}
		logger.Debug().Msgf("Appending stored expression at %s", identifier)
		logger.Trace().Msgf("Expression stored at %s is %s", identifier, stored)

		_, err = a.output.WriteString(stored)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Assemble) runAssemble() (regex string, err error) {
	if len(a.proc.lines) == 0 {
		return "", nil
	}

	regex, err = rassemble.Join(a.proc.lines)
	if err != nil {
		return "", err
	}

	a.proc.lines = []string{}
	// Wrap in non-capturing group to retain semantics
	return "(?:" + regex + ")", nil
}
func (a *Assemble) wrapCompletedAssembly(regex string) (result string) {
	if len(regex) == 0 && a.output.Len() == 0 {
		return ""
	} else if a.output.Len() > 0 && len(regex) > 0 {
		result = fmt.Sprint("(?:", a.output.String(), ")(?:", regex, ")")
	} else if a.output.Len() > 0 {
		result = fmt.Sprint("(?:", a.output.String(), ")")
	} else if len(regex) == 0 {
		result = ""
	} else {
		result = fmt.Sprint("(?:", regex, ")")
	}

	return result
}
