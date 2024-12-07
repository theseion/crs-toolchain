// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strconv"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/chore"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

var choreUpdateCopyrightCmd = createChoreUpdateCopyrightCommand()
var copyrightVariables struct {
	Version string
	Year    string
}

func init() {
	buildChoreUpdateCopyrightCommand()
}

func validateSemver(version string) error {
	_, err := semver.NewVersion(version)
	if err != nil {
		return err
	}
	return nil
}

func createChoreUpdateCopyrightCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update-copyright",
		Short: "Updates the copyright in setup, example setup, and rule files",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if copyrightVariables.Version == "" {
				return ErrUpdateCopyrightWithoutVersion
			}
			if err := validateSemver(copyrightVariables.Version); err != nil {
				return err
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			chore.UpdateCopyright(rootContext, copyrightVariables.Version, copyrightVariables.Year)
		},
	}
}

func buildChoreUpdateCopyrightCommand() {
	choreCmd.AddCommand(choreUpdateCopyrightCmd)
	choreUpdateCopyrightCmd.Flags().StringVarP(&copyrightVariables.Year, "year", "y", strconv.Itoa(time.Now().Year()), "Four digit year")
	choreUpdateCopyrightCmd.Flags().StringVarP(&copyrightVariables.Version, "version", "v", "", "Add this text as the version to the file.")
}

func rebuildChoreUpdateCopyrightCommand() {
	if choreUpdateCopyrightCmd != nil {
		choreUpdateCopyrightCmd.Parent().RemoveCommand(choreUpdateCopyrightCmd)
	}

	choreUpdateCopyrightCmd = createChoreUpdateCopyrightCommand()
	buildChoreUpdateCopyrightCommand()
}
