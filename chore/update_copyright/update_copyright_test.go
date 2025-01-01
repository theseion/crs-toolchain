// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package chore

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/suite"
)

type copyrightUpdateTestsTestSuite struct {
	suite.Suite
}

func TestRunUpdateCopyrightTestsTestSuite(t *testing.T) {
	suite.Run(t, new(copyrightUpdateTestsTestSuite))
}

// Test that the function updates the year in the file
func (s *copyrightUpdateTestsTestSuite) TestUpdateCopyrightTests_SetVersion() {
	contents := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#wiki-SecComponentSignature
#
SecComponentSignature "OWASP_CRS/4.0.0-rc1"
`
	expected := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.9.1.22
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2042 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#wiki-SecComponentSignature
#
SecComponentSignature "OWASP_CRS/9.1.22"
`
	version, err := semver.NewVersion("9.1.22")
	s.Require().NoError(err)
	out, err := updateRules(version, 2042, []byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

// Test that the function updates the year in the copyright, in the SecComponentSignature and the SecRule "ver" part
func (s *copyrightUpdateTestsTestSuite) TestUpdateCopyrightTests_SetYear() {
	contents := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 CRS project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.crs_setup_version=400"

SecRule &TX:crs_setup_version "@eq 0" \
    "id:901001,\
    phase:1,\
    deny,\
    status:500,\
    log,\
    auditlog,\
    msg:'ModSecurity CRS is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions',\
    ver:'OWASP_CRS/4.0.0-rc1',\
    severity:'CRITICAL'"

# -=[ Rules Version ]=-
#
# Rule version data is added to the "Producer" line of Section H of the Audit log:
#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)#seccomponentsignature
#
SecComponentSignature "OWASP_CRS/3.3.5"
`
	expected := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.99.12
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2041 CRS project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.crs_setup_version=49912"

SecRule &TX:crs_setup_version "@eq 0" \
    "id:901001,\
    phase:1,\
    deny,\
    status:500,\
    log,\
    auditlog,\
    msg:'ModSecurity CRS is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions',\
    ver:'OWASP_CRS/4.99.12',\
    severity:'CRITICAL'"

# -=[ Rules Version ]=-
#
# Rule version data is added to the "Producer" line of Section H of the Audit log:
#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)#seccomponentsignature
#
SecComponentSignature "OWASP_CRS/4.99.12"
`
	version, err := semver.NewVersion("4.99.12")
	s.Require().NoError(err)
	out, err := updateRules(version, 2041, []byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

// Test that the function adds a new line when the file does not end with a new line
func (s *copyrightUpdateTestsTestSuite) TestUpdateCopyrightTests_AddsNewLine() {
	contents := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.0-rc1`
	expected := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.99.12
`
	version, err := semver.NewVersion("4.99.12")
	s.Require().NoError(err)
	out, err := updateRules(version, 2041, []byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}

// Test that the function supports release candidate naming
func (s *copyrightUpdateTestsTestSuite) TestUpdateCopyrightTests_SupportsReleaseCandidateNaming() {
	contents := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.0.1
`
	expected := `# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.4.1.0-rc1
`
	version, err := semver.NewVersion("4.1.0-rc1")
	s.Require().NoError(err)
	out, err := updateRules(version, 2041, []byte(contents))
	s.Require().NoError(err)

	s.Equal(expected, string(out))
}
