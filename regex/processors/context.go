// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"fmt"
	"io"

	"github.com/coreruleset/crs-toolchain/v2/context"
)

type Context struct {
	rootContext       *context.Context
	singleRuleID      int
	singleChainOffset bool
	stash             map[string]string
}

// NewContext creates a new processor context using the `rootDir` as the root directory.
func NewContext(rootContext *context.Context) *Context {
	return &Context{
		rootContext:       rootContext,
		singleRuleID:      0,
		singleChainOffset: false,
		stash:             map[string]string{},
	}
}

// Dump dumps the context to the passed io.Writer.
func (ctx *Context) Dump(w io.Writer) {
	fmt.Printf("Context: %v\n", ctx)
}

// RootContext returns the root context of the toolchain
func (ctx *Context) RootContext() *context.Context {
	return ctx.rootContext
}
