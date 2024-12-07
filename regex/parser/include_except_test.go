// Copyright 2023 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type parserIncludeExceptTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	tempDir     string
	assemblyDir string
	includeDir  string
	excludeDir  string
}

func (s *parserIncludeExceptTestSuite) writeFile(contents string, directory string) string {
	filename := uuid.NewString() + ".ra"
	file, err := os.Create(path.Join(directory, filename))
	s.Require().NoError(err, "couldn't create %s file in directory %s", filename, directory)

	_, err = file.WriteString(contents)
	s.Require().NoError(err)

	return filepath.Join(directory, filename)
}

func TestParserRunIncludeExceptTestSuite(t *testing.T) {
	suite.Run(t, new(parserIncludeExceptTestSuite))
}

func (s *parserIncludeExceptTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "include-except-tests")
	s.Require().NoError(err)

	s.assemblyDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.assemblyDir, fs.ModePerm)
	s.Require().NoError(err)

	s.includeDir = path.Join(s.assemblyDir, "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	s.excludeDir = path.Join(s.assemblyDir, "exclude")
	err = os.MkdirAll(s.excludeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *parserIncludeExceptTestSuite) TearDownTest() {
	s.Require().NoError(os.RemoveAll(s.tempDir))
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_MoreExcludesThanIncludes() {
	includePath := s.writeFile(`\s*include1
leave me alone`, s.includeDir)
	excludePath := s.writeFile(`\s*include1
include2
[a-c]include4+
a*b|include3`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal("leave me alone\n", actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_EmptyLinesRemoved() {
	includePath := s.writeFile(`\s*include1
          
include2
leave me alone

`, s.includeDir)
	excludePath := s.writeFile(`include2

`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal(`\s*include1
leave me alone
`, actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_OutOfOrder() {
	includePath := s.writeFile(`
\s*include1
include2
a*b|include3
[a-c]include4+`, s.includeDir)
	excludePath := s.writeFile(`
include2
[a-c]include4+
a*b|include3`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal(`\s*include1`+"\n", actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_WithDefinitions() {
	includePath := s.writeFile(`##!> define homer _doughnut_
{{homer}}include1
include{{homer}}2
leave me alone
include3{{homer}}`, s.includeDir)
	excludePath := s.writeFile(`{{homer}}include1
include{{homer}}2
include3{{homer}}`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal("leave me alone\n", actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_DontPanicWhenInclusionsEmpty() {
	includePath := s.writeFile("include1", s.includeDir)
	excludePath := s.writeFile("include1", s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Empty(actual)
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_DontPanicWhenExclusionsEmpty() {
	includePath := s.writeFile("include1", s.includeDir)
	excludePath := s.writeFile("", s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprint("##!> include-except ", includePath, " ", excludePath), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal("include1\n", actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_SuffixReplacements() {
	includePath := s.writeFile(`no suffix1
suffix with@
suffix with~
no suffix 2`,
		s.includeDir)
	excludePath := s.writeFile("no suffix1", s.excludeDir)
	assemblyPath := s.writeFile(
		fmt.Sprintf(
			"##!> include-except %s %s -- %s %s %s %s", includePath, excludePath,
			"@", `[\s><]`,
			"~", `[^\s]`),
		s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)
	expected := `suffix with[\s><]
suffix with[^\s]
no suffix 2
`

	s.Equal(expected, actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_SuffixReplacements_WithEmptyString() {
	includePath := s.writeFile(`no suffix1
suffix with@
suffix with~
no suffix 2`,
		s.includeDir)
	excludePath := s.writeFile("no suffix1", s.excludeDir)
	assemblyPath := s.writeFile(
		fmt.Sprintf(
			"##!> include-except %s %s -- %s %s %s %s", includePath, excludePath,
			"@", `""`,
			"~", `""`),
		s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)
	expected := `suffix with
suffix with
no suffix 2
`

	s.Equal(expected, actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_MultipleExcludes() {
	includePath := s.writeFile(`\s*include1
leave me alone`, s.includeDir)
	excludePath1 := s.writeFile(`\s*include1
include2`, s.excludeDir)
	excludePath2 := s.writeFile(`[a-c]include4+
a*b|include3`, s.excludeDir)
	assemblyPath := s.writeFile(fmt.Sprintf("##!> include-except %s %s %s", includePath, excludePath1, excludePath2), s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)

	s.Equal("leave me alone\n", actual.String())
}

func (s *parserIncludeExceptTestSuite) TestIncludeExcept_SuffixReplacements_WithMultipleExclusions() {
	includePath := s.writeFile(`no suffix1
suffix with@
suffix with~
no suffix 2`,
		s.includeDir)
	excludePath1 := s.writeFile("no suffix1", s.excludeDir)
	excludePath2 := s.writeFile("no suffix 2", s.excludeDir)
	assemblyPath := s.writeFile(
		fmt.Sprintf(
			"##!> include-except %s %s %s -- %s %s %s %s", includePath, excludePath1, excludePath2,
			"@", `[\s><]`,
			"~", `[^\s]`),
		s.assemblyDir)

	assemblyFile, err := os.Open(assemblyPath)
	s.Require().NoError(err)
	defer assemblyFile.Close()

	parser := NewParser(s.ctx, assemblyFile)
	actual, _ := parser.Parse(false)
	expected := `suffix with[\s><]
suffix with[^\s]
`

	s.Equal(expected, actual.String())
}
