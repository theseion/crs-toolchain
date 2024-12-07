// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/suite"
)

type choreUpdateCopyrightTestSuite struct {
	suite.Suite
	tempDir  string
	dataDir  string
	rulesDir string
}

func (s *choreUpdateCopyrightTestSuite) SetupTest() {
	rebuildChoreCommand()
	rebuildChoreUpdateCopyrightCommand()

	tempDir, err := os.MkdirTemp("", "update-copyright-tests")
	s.Require().NoError(err)
	s.tempDir = tempDir

	s.dataDir = path.Join(s.tempDir, "regex-assembly")
	err = os.MkdirAll(s.dataDir, fs.ModePerm)
	s.Require().NoError(err)

	s.rulesDir = path.Join(s.tempDir, "rules")
	err = os.Mkdir(s.rulesDir, fs.ModePerm)
	s.Require().NoError(err)

	s.writeFile(path.Join(s.rulesDir, "TEST-900.conf"), `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file REQUEST-901-INITIALIZATION.conf initializes the Core Rules`)
	s.FileExists(path.Join(s.rulesDir, "TEST-900.conf"))

	s.writeFile(path.Join(s.tempDir, "crs-setup.conf.example"), `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.9.0-dev
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file is the crs-setup.conf.example shipped with CRS`)
	s.FileExists(path.Join(s.tempDir, "crs-setup.conf.example"))
}

func (s *choreUpdateCopyrightTestSuite) TearDownTest() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func TestRunUpdateCopyrightTestSuite(t *testing.T) {
	suite.Run(t, new(choreUpdateCopyrightTestSuite))
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_Version512() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "update-copyright", "-v", "5.1.2"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.1.2")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.tempDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.1.2")
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_Year2100() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "update-copyright", "-y", "2100", "-v", "7.1.22"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "2021-2100")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.tempDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "2021-2100")
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_ErrIfNoVersion() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "update-copyright", "-y", "2222"})
	cmd, err := rootCmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	s.Error(err, ErrUpdateCopyrightWithoutVersion)
}

func (s *choreUpdateCopyrightTestSuite) TestUpdateCopyright_DevRelease() {
	rootCmd.SetArgs([]string{"-d", s.tempDir, "chore", "update-copyright", "-v", "5.4.3-dev"})
	cmd, _ := rootCmd.ExecuteC()

	s.Equal("update-copyright", cmd.Name())

	// get year from file contents
	contents, err := os.ReadFile(path.Join(s.rulesDir, "TEST-900.conf"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev")
	s.NotContains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev-dev")

	// check that crs-setup.conf.example was also modified
	contents, err = os.ReadFile(path.Join(s.tempDir, "crs-setup.conf.example"))
	s.Require().NoError(err)
	s.Contains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev")
	s.NotContains(string(contents), "OWASP ModSecurity Core Rule Set ver.5.4.3-dev-dev")
}

func (s *choreUpdateCopyrightTestSuite) writeFile(filename string, contents string) {
	err := os.WriteFile(filename, []byte(contents), fs.ModePerm)
	s.Require().NoError(err)
}
