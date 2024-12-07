// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

type assembleTestSuite struct {
	suite.Suite
	ctx     *Context
	tempDir string
}

type fileFormatTestSuite assembleTestSuite

func (suite *assembleTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "assemble-test")
	suite.Require().NoError(err)
	rootContext := context.New(suite.tempDir, "toolchain.yaml")
	suite.ctx = NewContext(rootContext)
}

func (suite *assembleTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.Require().NoError(err)
}

func (suite *fileFormatTestSuite) SetupSuite() {
	var err error
	suite.tempDir, err = os.MkdirTemp("", "file-format-test")
	suite.Require().NoError(err)
	rootContext := context.New(suite.tempDir, "toolchain.yaml")
	suite.ctx = NewContext(rootContext)
}

func (suite *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.tempDir)
	suite.Require().NoError(err)
}

func TestRunAssembleTestSuite(t *testing.T) {
	suite.Run(t, new(assembleTestSuite))
	suite.Run(t, new(fileFormatTestSuite))
}

func (s *assembleTestSuite) TestNewAssemble() {
	assemble := NewAssemble(s.ctx)

	s.NotNil(assemble)
	s.Equal(assemble.proc.ctx.RootContext().RootDir(), s.tempDir)
	s.Equal(assemble.proc.ctx.RootContext().AssemblyDir(), s.tempDir+"/regex-assembly")
}

func (s *assembleTestSuite) TestAssemble_MultipleLines() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("homer")
	s.Require().NoError(err)
	err = assemble.ProcessLine("simpson")
	s.Require().NoError(err)
	output, err := assemble.Complete()

	s.Require().NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:homer|simpson))", output[0])
}

func (s *assembleTestSuite) TestAssemble_RegularExpressions() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r,]")
	s.Require().NoError(err)
	err = assemble.ProcessLine(".imps[a-c]{2}n")
	s.Require().NoError(err)
	output, err := assemble.Complete()

	s.Require().NoError(err)
	s.Len(output, 1)
	s.Equal("(?:(?:(?-s:home[,r]|.imps[a-c]{2}n)))", output[0])
}

func (s *assembleTestSuite) TestAssemble_InvalidRegularExpressionFails() {
	assemble := NewAssemble(s.ctx)
	err := assemble.ProcessLine("home[r")
	s.Require().NoError(err)

	_, err = assemble.Complete()
	s.Error(err)
}
