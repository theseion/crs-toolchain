// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "github.com/coreruleset/crs-toolchain/v2/logger"

	"github.com/coreruleset/crs-toolchain/v2/cmd"
)

// nolint: gochecknoglobals
var (
	version = "v0.0.0-dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	cmd.Execute(version, commit, date, builtBy)

}
