// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const DefaultLogLevel zerolog.Level = zerolog.InfoLevel

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"}).With().Caller().Logger()
	zerolog.SetGlobalLevel(DefaultLogLevel)
}

func SetGithubOutput(w io.Writer) zerolog.Logger {
	ghOutput := zerolog.ConsoleWriter{Out: w, TimeFormat: "03:04:05"}
	ghOutput.FormatLevel = func(i interface{}) string {
		var l string
		if ll, ok := i.(string); ok {
			switch ll {
			case zerolog.LevelTraceValue, zerolog.LevelDebugValue:
				l = "debug"
			case zerolog.LevelInfoValue:
				l = "notice"
			case zerolog.LevelWarnValue:
				l = "warn"
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
	ghOutput.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("::%s\n", i)
	}
	ghOutput.PartsExclude = []string{zerolog.TimestampFieldName, zerolog.CallerFieldName}
	ghOutput.PartsOrder = []string{
		zerolog.LevelFieldName,
		zerolog.MessageFieldName,
	}
	ghOutput.NoColor = true

	return log.Output(ghOutput).With().Caller().Logger()
}
