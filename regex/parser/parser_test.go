// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserTestSuite struct {
	suite.Suite
	reader io.Reader
}

func TestRunParserTestSuite(t *testing.T) {
	suite.Run(t, new(parserTestSuite))
}

func (s *parserTestSuite) TestParser_NewParser() {
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	expected := &Parser{
		ctx:       processors.NewContext(rootContext),
		src:       s.reader,
		dest:      &bytes.Buffer{},
		Flags:     make(map[rune]bool),
		Prefixes:  []string{},
		Suffixes:  []string{},
		variables: make(map[string]string),
		patterns: map[string]*regexp.Regexp{
			includePatternName:       regex.IncludeRegex,
			includeExceptPatternName: regex.IncludeExceptRegex,
			definitionPatternName:    regex.DefinitionRegex,
			commentPatternName:       regex.CommentRegex,
			flagsPatternName:         regex.FlagsRegex,
			prefixPatternName:        regex.PrefixRegex,
			suffixPatternName:        regex.SuffixRegex,
		},
	}
	actual := NewParser(processors.NewContext(rootContext), s.reader)

	s.Equal(expected, actual)
}

func (s *parserTestSuite) TestParser_ParseTwoComments() {
	reader := strings.NewReader("##! This is a comment.\n##! This is another line.\n")
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	parser := NewParser(processors.NewContext(rootContext), reader)

	actual, n := parser.Parse(false)
	expected := bytes.NewBufferString("")

	s.Equal(expected.String(), actual.String())
	s.Len(expected.String(), n)
}

func (s *parserTestSuite) TestIgnoresEmptyLines() {
	contents := "some line\n\nanother line"
	reader := strings.NewReader(contents)
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	parser := NewParser(processors.NewContext(rootContext), reader)
	actual, n := parser.Parse(false)

	expected := "some line\nanother line\n"
	s.Equal(expected, actual.String())
	s.Len(expected, n)
}

func (s *parserTestSuite) TestPanicsOnUnrecognizedFlag() {
	contents := "##!+ flag"
	reader := strings.NewReader(contents)
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	parser := NewParser(processors.NewContext(rootContext), reader)

	s.PanicsWithValue("flag 'f' is not supported", func() { parser.Parse(false) }, "should panic because flags are not supported")

}
