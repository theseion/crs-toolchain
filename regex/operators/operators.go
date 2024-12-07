// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"io"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

var logger = log.With().Str("component", "operators").Logger()

type Operator struct {
	name                          string
	details                       map[string]string
	lines                         []string
	stats                         *Stats
	ctx                           *processors.Context
	groupReplacementStringBuilder *strings.Builder
}

type ProcessorStack struct {
	processors []processors.IProcessor
}

type IOperator interface {
	Preprocess(io.Reader)
	Run(io.Reader)
}

func NewProcessorStack() ProcessorStack {
	return ProcessorStack{}
}

func (p *ProcessorStack) push(processor processors.IProcessor) {
	p.processors = append(p.processors, processor)
}

func (p *ProcessorStack) pop() (processors.IProcessor, error) {
	top, err := p.top()
	if err != nil {
		return nil, err
	}

	p.processors = p.processors[:len(p.processors)-1]
	return top, nil
}

func (p *ProcessorStack) top() (processors.IProcessor, error) {
	logger.Trace().Msgf("Processor stack len: %d\n", len(p.processors))
	if len(p.processors) == 0 {
		return nil, errors.New("stack is empty")
	}
	return p.processors[len(p.processors)-1], nil
}
