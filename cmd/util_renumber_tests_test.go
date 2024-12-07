// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/util"
)

type renumberTestsTestSuite struct {
	suite.Suite
	tempDir  string
	testsDir string
}

func (s *renumberTestsTestSuite) writeTestFile(filename string, contents string) {
	prefix := filename[0:3]
	rulesDir := path.Join(s.testsDir, "_prefix_"+prefix+"_suffix_")
	err := os.Mkdir(rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	err = os.WriteFile(path.Join(rulesDir, filename), []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}

func (s *renumberTestsTestSuite) readTestFile(filename string) string {
	prefix := filename[0:3]
	rulesDir := path.Join(s.testsDir, "_prefix_"+prefix+"_suffix_")
	contents, err := os.ReadFile(path.Join(rulesDir, filename))
	s.Require().NoError(err)
	return string(contents)
}

func (s *renumberTestsTestSuite) captureStdout() *os.File {
	read, write, err := os.Pipe()
	s.Require().NoError(err)

	realStdout := os.Stdout
	os.Stdout = write
	s.T().Cleanup(func() {
		os.Stdout = realStdout
	})
	return read
}

func (s *renumberTestsTestSuite) SetupTest() {
	rebuildUtilCommand()
	rebuildRenumberTestsCommand()

	tempDir, err := os.MkdirTemp("", "renumber-tests-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	dataDir := path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.testsDir = path.Join(s.tempDir, "tests", "regression", "tests")
	err = os.MkdirAll(s.testsDir, fs.ModePerm)
	s.Require().NoError(err)
}

func (s *renumberTestsTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunRenumberTestsTestSuite(t *testing.T) {
	suite.Run(t, new(renumberTestsTestSuite))
}

func (s *renumberTestsTestSuite) TestRenumberTests_WithYaml() {
	s.writeTestFile("123456.yaml", "test_id: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	actual := s.readTestFile("123456.yaml")
	s.Equal("test_id: 1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_WithYml() {
	s.writeTestFile("123456.yml", "test_id: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	actual := s.readTestFile("123456.yml")
	s.Equal("test_id: 1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_NormalRuleId() {
	s.writeTestFile("123456.yaml", "")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("renumber-tests", cmd.Name())

	args := cmd.Flags().Args()
	s.Len(args, 1)
	s.Equal("123456", args[0])
}

func (s *renumberTestsTestSuite) TestRenumberTests_NoArgument() {
	rootCmd.SetArgs([]string{"util", "renumber-tests"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, or flag, found nothing")
}

func (s *renumberTestsTestSuite) TestRenumberTests_ArgumentAndAllFlag() {
	rootCmd.SetArgs([]string{"util", "renumber-tests", "123456", "--all"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "expected RULE_ID, or flag, found multiple")
}

func (s *renumberTestsTestSuite) TestRenumberTests_Dash() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "invalid argument '-'")
}

func (s *renumberTestsTestSuite) TestRenumberTests_CheckOnly() {
	contents := "test_id: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-c", "123456"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "Tests are not properly numbered")

	actual := s.readTestFile("123456.yaml")
	s.Equal(contents, actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_GitHubOutput() {
	read := s.captureStdout()

	contents := "test_id: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-cao", "github"})
	_, err := rootCmd.ExecuteC()

	s.ErrorIs(err, &util.TestNumberingError{})

	buffer := make([]byte, 1024)
	_, err = read.Read(buffer)
	s.Require().NoError(err)

	output := string(buffer)
	s.Contains(output, "::warning::Test file not properly numbered")
	s.Contains(output, "::error::")
	s.Contains(output, "Please run `crs-toolchain util renumber-tests --all`")
}

func (s *renumberTestsTestSuite) TestRenumberTests_Legacy_WithYaml() {
	s.writeTestFile("123456.yaml", "test_title: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	actual := s.readTestFile("123456.yaml")
	s.Equal("test_title: 123456-1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_Legacy_WithYml() {
	s.writeTestFile("123456.yml", "test_title: homer")
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "123456"})
	_, err := rootCmd.ExecuteC()
	s.Require().NoError(err)

	actual := s.readTestFile("123456.yml")
	s.Equal("test_title: 123456-1\n", actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_Legacy_CheckOnly() {
	contents := "test_title: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-c", "123456"})
	_, err := rootCmd.ExecuteC()

	s.EqualError(err, "Tests are not properly numbered")

	actual := s.readTestFile("123456.yaml")
	s.Equal(contents, actual)
}

func (s *renumberTestsTestSuite) TestRenumberTests_Legacy_GitHubOutput() {
	read := s.captureStdout()

	contents := "test_title: homer"
	s.writeTestFile("123456.yaml", contents)
	rootCmd.SetArgs([]string{"-d", s.tempDir, "util", "renumber-tests", "-cao", "github"})
	_, err := rootCmd.ExecuteC()

	s.ErrorIs(err, &util.TestNumberingError{})

	buffer := make([]byte, 1024)
	_, err = read.Read(buffer)
	s.Require().NoError(err)

	output := string(buffer)
	s.Contains(output, "::warning::Test file not properly numbered")
	s.Contains(output, "::error::")
	s.Contains(output, "Please run `crs-toolchain util renumber-tests --all`")
}
