// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/rs/zerolog"

	loggerConfig "github.com/coreruleset/crs-toolchain/logger"
)

// The types in this file satisfy the interface of pflag.Value.
// Using the pflag.Value interface makes it possible to validate
// flag values at parse time, as opposed to using `persistentPreRunE`,
// which would also work, except that persistent run functions will run
// in the child command first, which means that a global flag, like
// `--log-level`, would only be processed `after` other flags, and
// logging as part of flag value validation would then be useless.

type outputType string
type logLevel string
type workingDirectory string
type configurationFileName string

// TODO: Use proper types that encapsulate printing logic
const (
	text   outputType = "text"
	gitHub outputType = "github"
)

func (o *outputType) String() string {
	return string(*o)
}

func (o *outputType) Set(value string) error {
	switch value {
	case string(gitHub):
		logger = loggerConfig.SetGithubOutput(os.Stdout)
		fallthrough
	case string(text):
		rootValues.output = outputType(value)
		return nil
	default:
		return fmt.Errorf("invalid option for output: '%s'", value)
	}
}

func (o *outputType) Type() string {
	return "output type"
}

func (l *logLevel) String() string {
	level, _ := zerolog.ParseLevel(string(*l))
	return level.String()
}

func (l *logLevel) Set(value string) error {
	parsedLogLevel, err := zerolog.ParseLevel(value)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to parse log level '%s'", value)
		return err
	}
	// Set the global log level as a side effect. This is what we
	// really want to do.
	zerolog.SetGlobalLevel(parsedLogLevel)
	*l = logLevel(value)
	logger.Trace().Msgf("Set log level to '%s'", parsedLogLevel)

	return nil
}

func (l *logLevel) Type() string {
	return "log level"
}

func (w *workingDirectory) String() string {
	return string(*w)
}

func (w *workingDirectory) Set(value string) error {
	absPath, err := filepath.Abs(value)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to construct absolute path from %s", value)
		return err
	}

	root, err := findRootDirectory(absPath)
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to find root directory from %s", absPath)
		return err
	}

	logger.Debug().Msgf("Resolved root directory %s", root)
	*w = workingDirectory(root)
	return nil
}

func (w *workingDirectory) Type() string {
	return "working directory"
}

func (c *configurationFileName) String() string {
	return string(*c)
}

func (c *configurationFileName) Set(value string) error {
	*c = configurationFileName(value)
	return nil
}

func (c *configurationFileName) Type() string {
	return "configuration filename"
}

func findRootDirectory(startPath string) (string, error) {
	logger.Trace().Msgf("Searching for root directory starting at %s", startPath)
	dataPath := path.Join("regex-assembly")
	currentPath := startPath
	// root directory only will have a separator as the last rune
	for currentPath[len(currentPath)-1] != filepath.Separator {

		_, err := os.Stat(path.Join(currentPath, dataPath))
		if err != nil {
			currentPath = path.Dir(currentPath)
			logger.Trace().Msgf("Root directory not found yet. Trying %s", currentPath)
			continue
		}

		return currentPath, nil
	}

	return "", errors.New("failed to find root directory")
}
