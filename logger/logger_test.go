// Copyright 2024 OWASP ModSecurity Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type loggerTestSuite struct {
	suite.Suite
	out    *bytes.Buffer
	logger zerolog.Logger
}

func TestRunLoggerTestSuite(t *testing.T) {
	suite.Run(t, new(loggerTestSuite))
}

var testJsonBase = []struct {
	name    string
	text    string
	logType zerolog.Level
	want    string
}{
	{
		name:    "JsonBaseOutput",
		text:    "hello",
		logType: zerolog.InfoLevel,
		want:    "message\":\"hello\"",
	},
}

var testConsoleBase = []struct {
	name    string
	text    string
	logType zerolog.Level
	want    string
}{
	{
		name:    "BaseConsoleOutput",
		text:    "hello",
		logType: zerolog.InfoLevel,
		want:    "INF hello component=parser-test",
	},
}

var testGithub = []struct {
	name    string
	text    string
	logType zerolog.Level
	want    string
}{
	{
		name:    "TestGithubInfoOutput",
		text:    "this is an info message",
		logType: zerolog.InfoLevel,
		want:    "::notice ::this is an info message",
	},
	{
		name:    "TestGithubWarningOutput",
		text:    "this is a warning message",
		logType: zerolog.WarnLevel,
		want:    "::warn ::this is a warning message",
	},
	{
		name:    "TestGithubTraceOutput",
		text:    "this is a trace message that will show as debug",
		logType: zerolog.TraceLevel,
		want:    "::debug ::this is a trace message that will show as debug",
	},
	{
		name:    "TestGithubDebugOutput",
		text:    "this is a debug message",
		logType: zerolog.DebugLevel,
		want:    "::debug ::this is a debug message",
	},
}

func (s *loggerTestSuite) SetupTest() {
	// reset logger
	s.out = &bytes.Buffer{}
	s.logger = zerolog.New(s.out).With().Str("component", "parser-test").Logger()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
}

func (s *loggerTestSuite) TestJsonOutput() {
	for _, t := range testJsonBase {
		s.Run(t.name, func() {
			s.logger.WithLevel(t.logType).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}

func (s *loggerTestSuite) TestConsoleOutput() {
	s.logger = s.logger.Output(zerolog.ConsoleWriter{Out: s.out, NoColor: true, TimeFormat: "03:04:05"})
	for _, t := range testConsoleBase {
		s.Run(t.name, func() {
			s.logger.WithLevel(t.logType).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}

//s.log = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "03:04:05"}).With().Caller().Logger()

func (s *loggerTestSuite) TestSetGithubOutput() {
	// send logs to buffer
	logger := SetGithubOutput(s.out)
	for _, t := range testGithub {
		s.Run(t.name, func() {
			logger.WithLevel(t.logType).Msg(t.text)
			s.Contains(s.out.String(), t.want)
			s.out.Reset()
		})
	}
}
