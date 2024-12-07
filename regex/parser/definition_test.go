// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserDefinitionTestSuite struct {
	suite.Suite
	ctx    *processors.Context
	reader io.Reader
}

func TestParserDefinitionsTestSuite(t *testing.T) {
	suite.Run(t, new(parserDefinitionTestSuite))
}

func (s *parserDefinitionTestSuite) SetupSuite() {
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	s.reader = strings.NewReader("##!> define this-is-a-text [a-zA-J]+8\n" +
		"##!> define this-is-another-text [0-9](pine|apple)\n" +
		"{{this-is-a-text}} to see if definitions work.\n" +
		"Second text for {{this-is-another-text}}.\n")
}

func (s *parserDefinitionTestSuite) TestParserDefinition_BasicTest() {
	parser := NewParser(s.ctx, s.reader)
	actual, _ := parser.Parse(false)
	expected := bytes.NewBufferString("[a-zA-J]+8 to see if definitions work.\nSecond text for [0-9](pine|apple).\n")

	s.Greater(len(parser.variables), 0)
	s.Equal(parser.variables["this-is-a-text"], "[a-zA-J]+8", "failed to found definition variables in map")
	s.Equal(parser.variables["this-is-another-text"], "[0-9](pine|apple)", "failed to found definition variables in map")
	s.Equal(expected.String(), actual.String())
}

func (s *parserIncludeWithDefinitions) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "include-multi-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.includeDir = path.Join(s.tempDir, "regex-assembly", "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	for i := 0; i < 4; i++ {
		file, err := os.Create(path.Join(s.tempDir, fmt.Sprintf("multi-definitions-%d.ra", i)))
		s.Require().NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf(
				"##!> include %s\n"+
					"##!> define this-is-a-text [a-zA-J]+8\n"+
					"##!> define this-is-another-text [0-9](pine|apple)\n"+
					"{{this-is-a-text}} to see if definitions work.\n"+
					"Second text for {{this-is-another-text}}.\n", file.Name()))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(
				fmt.Sprintf(
					"##!> include %s\n"+
						"This is comment %d.\n"+
						"{{this-is-a-text}} to see if definitions work when included\n", file.Name(), i))
			s.Require().NoError(err, "writing temp include file failed")
		}
	}
}
