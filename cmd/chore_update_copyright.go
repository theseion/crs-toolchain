// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/spf13/cobra"

	copyright "github.com/coreruleset/crs-toolchain/v2/chore/update_copyright"
	"github.com/coreruleset/crs-toolchain/v2/context"
)

var choreUpdateCopyrightCmd = createChoreUpdateCopyrightCommand()
var copyrightVariables struct {
	Version      string
	Year         uint16
	IgnoredPaths []string
}
var copyrightParsedVariables struct {
	version *semver.Version
}

func init() {
	buildChoreUpdateCopyrightCommand()
}

func createChoreUpdateCopyrightCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update-copyright",
		Short: "Updates the copyright in setup, example setup, and rule files",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if copyrightVariables.Version == "" {
				return ErrUpdateCopyrightWithoutVersion
			}
			version, err := semver.NewVersion(copyrightVariables.Version)
			if err != nil {
				return err
			}
			copyrightParsedVariables.version = version

			if copyrightVariables.Year < 1970 || copyrightVariables.Year > 9999 {
				return fmt.Errorf("year outside of valid range [1970, 9999]: %d", copyrightVariables.Year)
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			copyright.UpdateCopyright(rootContext, copyrightParsedVariables.version, copyrightVariables.Year, copyrightVariables.IgnoredPaths)
		},
	}
}

func buildChoreUpdateCopyrightCommand() {
	choreCmd.AddCommand(choreUpdateCopyrightCmd)
	choreUpdateCopyrightCmd.Flags().Uint16VarP(&copyrightVariables.Year, "year", "y", uint16(time.Now().Year()), "Four digit year")
	choreUpdateCopyrightCmd.Flags().StringVarP(&copyrightVariables.Version, "version", "v", "", "Add this text as the version to the file.")
	choreUpdateCopyrightCmd.Flags().StringArrayVarP(&copyrightVariables.IgnoredPaths, "ignore", "i", []string{}, "Comma separated list of paths to ignore")
}

func rebuildChoreUpdateCopyrightCommand() {
	if choreUpdateCopyrightCmd != nil {
		choreUpdateCopyrightCmd.Parent().RemoveCommand(choreUpdateCopyrightCmd)
	}

	choreUpdateCopyrightCmd = createChoreUpdateCopyrightCommand()
	buildChoreUpdateCopyrightCommand()
}
