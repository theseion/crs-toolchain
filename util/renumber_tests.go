// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
)

var logger = log.With().Str("component", "renumber-tests").Logger()

type TestNumberingError struct{}

func (t *TestNumberingError) Error() string {
	return "Tests are not properly numbered"
}

type TestRenumberer struct{}

func NewTestRenumberer() *TestRenumberer {
	return &TestRenumberer{}
}

func (t *TestRenumberer) RenumberTests(checkOnly bool, gitHubOutput bool, ctxt *context.Context) error {
	failed := false
	err := filepath.WalkDir(ctxt.RegressionTestsDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// abort
			return err
		}
		if d.IsDir() {
			// continue
			return nil
		}

		if err := t.processFile(path, checkOnly, gitHubOutput); err != nil {
			failed = true
			// continue
			return nil
		}
		// continue
		return nil
	})
	if err != nil {
		logger.Error().Err(err).Msg("failed to renumber tests")
		return err
	}
	if failed {
		if gitHubOutput {
			fmt.Println("::error::All test files need to be properly numbered.",
				"Please run `crs-toolchain util renumber-tests --all`")
		}
		return &TestNumberingError{}
	}
	return nil
}

func (t *TestRenumberer) RenumberTest(filePath string, checkOnly bool, ctxt *context.Context) error {
	return t.processFile(filePath, checkOnly, false)
}

func (t *TestRenumberer) processFile(filePath string, checkOnly bool, gitHubOutput bool) error {
	found := regex.RuleIdTestFileNameRegex.FindStringSubmatch(path.Base(filePath))
	if found == nil {
		// Skip other files
		return nil
	}
	ruleId := found[1]

	logger.Info().Msgf("Processing %s", ruleId)

	contents, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	output, err := t.processYaml(ruleId, contents)
	if err != nil {
		return err
	}

	if bytes.Equal(contents, output) {
		return nil
	}

	if gitHubOutput {
		fmt.Printf("::warning::Test file not properly numbered: %s\n", path.Base(filePath))
	}

	if checkOnly {
		return &TestNumberingError{}
	}

	return os.WriteFile(filePath, output, fs.ModePerm)
}

func (t *TestRenumberer) processYaml(ruleId string, contents []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Split(bufio.ScanLines)
	output := new(bytes.Buffer)
	writer := bufio.NewWriter(output)
	index := 0
	idCount := 0
	titleCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		matches := regex.TestIdRegex.FindStringSubmatch(line)
		if matches != nil {
			idCount++
			if idCount > index {
				index++
			}
			line = fmt.Sprint(matches[1], " ", index)
		}
		// legacy support
		matches = regex.TestTitleRegex.FindStringSubmatch(line)
		if matches != nil {
			titleCount++
			if titleCount > index {
				index++
			}
			line = fmt.Sprint(matches[1], " ", ruleId, "-", index)
		}

		if _, err := writer.WriteString(line); err != nil {
			return nil, err
		}
		if _, err := writer.WriteRune('\n'); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	outputBytes := t.formatEndOfFile(bytes.Split(output.Bytes(), []byte("\n")))
	return bytes.Join(outputBytes, []byte("\n")), nil
}

func (t *TestRenumberer) formatEndOfFile(lines [][]byte) [][]byte {
	emptyBytes := []byte{}
	eof := len(lines) - 1
	if eof < 0 {
		// Lines will be joined with newlines, so
		// two empty lines will result in a single
		// newline character
		return append(lines, emptyBytes, emptyBytes)
	}

	for i := eof; i >= 0; i-- {
		line := lines[i]
		if len(bytes.TrimSpace(line)) == 0 {
			eof--
		} else {
			break
		}
	}
	// Append a single empty line, which will be joined
	// to the others by newline
	return append(lines[:eof+1], emptyBytes)
}
