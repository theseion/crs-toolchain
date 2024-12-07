// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/util"
)

// renumberTestsCommand represents the update command
var renumberTestsCommand = createRenumberTestsCommand()

func init() {
	buildRenumberTestsCommand()
}

func createRenumberTestsCommand() *cobra.Command {

	return &cobra.Command{
		Use: "renumber-tests RULE_ID",
		Short: `Renumber all CRS tests, so that they are sequential in every file.

RULE_ID is the ID of the rule, e.g., 932100, or the test file name.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected RULE_ID, or flag, found nothing")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected RULE_ID, or flag, found multiple")
			} else if len(args) == 1 && args[0] == "-" {
				return errors.New("invalid argument '-'")
			}

			return nil
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkOnly, err := cmd.Flags().GetBool("check")
			if err != nil {
				return err
			}
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				return err
			}

			// The following errors are not command related
			cmd.SilenceUsage = true
			if rootValues.output == gitHub {
				cmd.SilenceErrors = true
			}
			ctxt := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			renumberer := util.NewTestRenumberer()
			if processAll {
				return renumberer.RenumberTests(checkOnly, rootValues.output == gitHub, ctxt)
			}

			filenameArg := args[0]
			filePath, err := parseFilePath(filenameArg, ctxt)
			if err != nil {
				return err
			}
			return renumberer.RenumberTest(filePath, checkOnly, ctxt)
		},
	}

}

func buildRenumberTestsCommand() {
	utilCmd.AddCommand(renumberTestsCommand)
	renumberTestsCommand.PersistentFlags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
renumber all test files`)
	renumberTestsCommand.Flags().BoolP("check", "c", false, `Do not write changes, simply report on files that would be renumbered`)
}

func rebuildRenumberTestsCommand() {
	if renumberTestsCommand != nil {
		renumberTestsCommand.Parent().RemoveCommand(renumberTestsCommand)
	}

	renumberTestsCommand = createRenumberTestsCommand()
	buildRenumberTestsCommand()
}

func parseFilePath(ruleOrFileName string, ctxt *context.Context) (string, error) {
	// We have no guarantee that the extension will be `.yaml`, it, so
	// try to find the file and get the actual name from the file system.
	extension := path.Ext(ruleOrFileName)
	ruleOrFileName = ruleOrFileName[:len(ruleOrFileName)-len(extension)]
	candidates, err := filepath.Glob(path.Join(ctxt.RegressionTestsDir(), "*", ruleOrFileName) + ".*")
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no test file found for argument %s", ruleOrFileName)
	}

	if len(candidates) > 1 {
		return "", fmt.Errorf("found multiple test files matching argument %s: %v", ruleOrFileName, candidates)
	}
	return candidates[0], nil
}
