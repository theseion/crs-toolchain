// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"github.com/coreruleset/crs-toolchain/v2/configuration"
)

type Context struct {
	rootDirectory                string
	rulesDirectory               string
	assemblyFilesDirectory       string
	includeFilesDirectory        string
	excludeFilesDirectory        string
	regressionTestFilesDirectory string
	configuration                *configuration.Configuration
}

func New(rootDir string, configurationFileName string) *Context {
	configurationDirectory := rootDir + "/regex-assembly"
	return NewWithConfiguration(rootDir, configuration.New(configurationDirectory, configurationFileName))
}

func NewWithConfiguration(rootDir string, configuration *configuration.Configuration) *Context {
	return &Context{
		rootDirectory:                rootDir,
		rulesDirectory:               rootDir + "/rules",
		assemblyFilesDirectory:       rootDir + "/regex-assembly",
		includeFilesDirectory:        rootDir + "/regex-assembly/include",
		excludeFilesDirectory:        rootDir + "/regex-assembly/exclude",
		regressionTestFilesDirectory: rootDir + "/tests/regression/tests",
		configuration:                configuration,
	}
}

// RootDir returns the root of the CRS directory structure.
func (ctx *Context) RootDir() string {
	return ctx.rootDirectory
}

// DataDir returns the 'regex-assembly' directory.
func (ctx *Context) AssemblyDir() string {
	return ctx.assemblyFilesDirectory
}

// IncludeDir returns the 'include' directory. Used to include files that don't have an absolute path.
func (ctx *Context) IncludesDir() string {
	return ctx.includeFilesDirectory
}

// ExcludesDir returns the 'exclude' directory. Used for exclude files that don't have an absolute path.
func (ctx *Context) ExcludesDir() string {
	return ctx.excludeFilesDirectory
}

// RulesDir returns the 'rules' directory.
func (ctx *Context) RulesDir() string {
	return ctx.rulesDirectory
}

// RegressionTestsDir returns the 'tests' directory of regression tests.
func (ctx *Context) RegressionTestsDir() string {
	return ctx.regressionTestFilesDirectory
}

func (ctx *Context) Configuration() *configuration.Configuration {
	return ctx.configuration
}
