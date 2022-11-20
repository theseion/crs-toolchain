// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const DefaultLogLevel zerolog.Level = zerolog.InfoLevel

var consoleOutput = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"}

func init() {
	log.Logger = log.Output(consoleOutput).With().Caller().Logger()
	zerolog.SetGlobalLevel(DefaultLogLevel)
}

// SetGithubOutput changes the standard logging format to be compatible with GitHub's.
// See https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#example-creating-an-annotation-for-an-error
// Levels on github are:
// - debug, notice, error, warning
// Another possibility is to add the following strings between the level and the message:
// file={name},line={line},endLine={endLine},title={title}
func SetGithubOutput() zerolog.Logger {
	// the following formatlevel loosely translates from posix levels to github levels
	consoleOutput.FormatLevel = func(i interface{}) string {
		var l string
		if ll, ok := i.(string); ok {
			switch ll {
			case zerolog.LevelTraceValue, zerolog.LevelDebugValue:
				l = "debug"
			case zerolog.LevelInfoValue:
				l = "notice "
			case zerolog.LevelWarnValue:
				l = "warn "
			case zerolog.LevelErrorValue, zerolog.LevelFatalValue, zerolog.LevelPanicValue:
				l = "error "
			default:
				l = "???"
			}
		} else {
			if i == nil {
				l = "???"
			}
		}
		return fmt.Sprintf("::%s", l)
	}
	consoleOutput.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("::%s", i)
	}
	consoleOutput.PartsExclude = []string{zerolog.TimestampFieldName}
	return zerolog.New(consoleOutput).With().Logger()
}
