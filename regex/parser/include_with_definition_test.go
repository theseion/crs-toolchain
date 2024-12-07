// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserIncludeWithDefinitions struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile []*os.File
}

func TestRunParserIncludeWithDefinitionsTestSuite(t *testing.T) {
	suite.Run(t, new(parserIncludeWithDefinitions))
}

func (s *parserIncludeWithDefinitions) TestParser_IncludeWithDefinitions() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString(
		"This is comment 3.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 2.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"This is comment 1.\n" +
			"[a-zA-J]+8 to see if definitions work when included\n" +
			"[a-zA-J]+8 to see if definitions work.\n" +
			"Second text for [0-9](pine|apple).\n")

	s.NotEmpty(parser.variables)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found definition variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found definition variables in map")
	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeWithDefinitions) TestParser_DanglingDefinitions() {
	// send logs to buffer
	out := &bytes.Buffer{}
	log := zerolog.New(out)
	logger = log.With().Str("component", "parser-test").Logger()

	reader := strings.NewReader("##!> define hello world\n{{hello}}\n{{hallo}}\n")
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	parser := NewParser(processors.NewContext(rootContext), reader)

	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString("world\n{{hallo}}\n")
	s.Equal(expected.String(), actual.String())

	s.Contains(out.String(), "no match found for definition: {{hallo}}")
}
