// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	loggerConfig "github.com/coreruleset/crs-toolchain/v2/logger"
)

type rootTestSuite struct {
	suite.Suite
	tempDir string
	dataDir string
}

func (s *rootTestSuite) SetupTest() {
	rebuildRootCommand()
	rebuildRegexCommand()
	zerolog.SetGlobalLevel(defaultLogLevel)

	tempDir, err := os.MkdirTemp("", "root-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)
}

func (s *rootTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunRootTestSuite(t *testing.T) {
	suite.Run(t, new(rootTestSuite))
}

func (s *rootTestSuite) TestRoot_NoArguments() {
	rootCmd.SetArgs([]string{})
	cmd, err := rootCmd.ExecuteC()

	s.Equal("crs-toolchain", cmd.Name())
	s.Require().NoError(err)
}

func (s *rootTestSuite) TestRoot_LogLevelDefault() {
	rootCmd.SetArgs([]string{})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.False(logLevelFlag.Changed)

	s.Equal(loggerConfig.DefaultLogLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelChanged() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "--log-level", "debug", "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_LogLevelInvalidShouldBeDefault() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "--log-level", "bizarre", "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.GlobalLevel(), loggerConfig.DefaultLogLevel)
}

func (s *rootTestSuite) TestRoot_LogLevelAllowedAnywhere() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "regex", "generate", "--log-level", "debug", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	logLevelFlag := cmd.Flags().Lookup("log-level")
	s.NotNil(logLevelFlag)
	s.True(logLevelFlag.Changed)

	s.Equal(zerolog.DebugLevel, zerolog.GlobalLevel())
}

func (s *rootTestSuite) TestRoot_AbsoluteWorkingDirectory() {
	s.writeDataFile("123456.ra", "")
	rootCmd.SetArgs([]string{"--directory", s.tempDir, "regex", "generate", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)

	s.Equal(path.Clean(s.tempDir), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestRoot_RelativeWorkingDirectory() {
	rootCmd.SetArgs([]string{"-d", "../testDir", "regex", "generate", "-"})
	cwd, err := os.Getwd()
	s.Require().NoError(err)
	parentCwd := path.Dir(cwd)
	err = os.MkdirAll(path.Join(parentCwd, "testDir", "regex-assembly"), fs.ModePerm)
	s.Require().NoError(err)
	defer os.RemoveAll(path.Join(parentCwd, "testDir"))

	cmd, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	workingDirectoryFlag := cmd.Flags().Lookup("directory")
	s.NotNil(workingDirectoryFlag)
	s.True(workingDirectoryFlag.Changed)
	s.True(path.IsAbs(workingDirectoryFlag.Value.String()))

	s.Equal(path.Join(parentCwd, "testDir"), workingDirectoryFlag.Value.String())
}

func (s *rootTestSuite) TestFindRootDirectoryInRoot() {
	root, err := findRootDirectory(s.tempDir)
	s.Require().NoError(err)
	s.Equal(s.tempDir, root)
}

func (s *rootTestSuite) TestFindRootDirectoryInUtil() {
	root, err := findRootDirectory(path.Join(s.tempDir, "util"))
	s.Require().NoError(err)
	s.Equal(s.tempDir, root)
}

func (s *rootTestSuite) TestFindRootDirectoryInData() {
	root, err := findRootDirectory(s.dataDir)
	s.Require().NoError(err)
	s.Equal(s.tempDir, root)
}

func (s *rootTestSuite) TestFindRootDirectoryInInclude() {
	includeDir := path.Join(s.dataDir, "include")
	err := os.Mkdir(includeDir, fs.ModePerm)
	s.Require().NoError(err)
	root, err := findRootDirectory(includeDir)
	s.Require().NoError(err)
	s.Equal(s.tempDir, root)
}

func (s *rootTestSuite) TestFindRootDirectoryInRules() {
	err := os.Mkdir(path.Join(s.tempDir, "rules"), fs.ModePerm)
	s.Require().NoError(err)

	root, err := findRootDirectory(path.Join(s.tempDir, "rules"))
	s.Require().NoError(err)
	s.Equal(s.tempDir, root)
}

func (s *rootTestSuite) TestFindRootDirectoryFails() {
	_, err := findRootDirectory(os.TempDir())
	s.Error(err)
}

func (s *rootTestSuite) writeDataFile(filename string, contents string) {
	err := os.WriteFile(path.Join(s.dataDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
