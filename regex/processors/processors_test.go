// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

type processorTestSuite struct {
	suite.Suite
	ctx *Context
}

func (s *processorTestSuite) SetupTest() {
	rootContext := context.New(os.TempDir(), "toolchain.yaml")
	s.ctx = NewContext(rootContext)
}

func TestRunProcessorTestSuite(t *testing.T) {
	suite.Run(t, new(processorTestSuite))
}

func (s *processorTestSuite) TestProcessor_New() {
	expected := &Processor{
		ctx:   s.ctx,
		lines: []string{},
	}

	actual := NewProcessor(s.ctx)
	s.Equal(expected, actual)
}

func (s *processorTestSuite) TestProcessor_NewWithContext() {
	expected := &Processor{
		ctx:   s.ctx,
		lines: []string{},
	}

	actual := NewProcessor(s.ctx)
	s.Equal(expected, actual)
}
