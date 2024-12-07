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

type parserMultiIncludeTestSuite struct {
	suite.Suite
	ctx         *processors.Context
	reader      io.Reader
	tempDir     string
	includeDir  string
	includeFile []*os.File
}

func TestRunParserMultiIncludeTestSuite(t *testing.T) {
	suite.Run(t, new(parserMultiIncludeTestSuite))
}

// Test Suite to perform multiple inclusions
func (s *parserMultiIncludeTestSuite) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "include-multi-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.includeDir = path.Join(s.tempDir, "regex-assembly", "include")
	err = os.MkdirAll(s.includeDir, fs.ModePerm)
	s.Require().NoError(err)

	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
	for i := 0; i < 4; i++ {
		file, err := os.Create(path.Join(s.includeDir, fmt.Sprintf("multi-include-%d.ra", i)))
		s.Require().NoError(err, "couldn't create %s file", file.Name())
		if i == 0 {
			// Only the initial include goes to the reader
			s.reader = strings.NewReader(fmt.Sprintf("##!> include %s\nThis is comment %d.\n", file.Name(), i))
		}
		s.includeFile = append(s.includeFile, file)
		// Write to file i-1
		if i > 0 {
			_, err := s.includeFile[i-1].WriteString(fmt.Sprintf("##!> include %s\nThis is comment %d.\n", file.Name(), i))
			s.Require().NoError(err, "writing temp include file failed")
		}
	}
}

func (s *parserMultiIncludeTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *parserMultiIncludeTestSuite) TestParserMultiInclude_FromMultiFile() {
	parser := NewParser(s.ctx, s.reader)
	actual, n := parser.Parse(false)
	expected := bytes.NewBufferString(
		"This is comment 3.\n" +
			"This is comment 2.\n" +
			"This is comment 1.\n" +
			"This is comment 0.\n")

	s.Equal(expected.String(), actual.String())
	s.Equal(expected.Len(), n)
}
