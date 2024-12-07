// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// updateCmd represents the update command
var updateCmd = createUpdateCommand()

func init() {
	buildUpdateCommand()
}

func createUpdateCommand() *cobra.Command {

	return &cobra.Command{
		Use:   "update [RULE_ID]",
		Short: "Update regular expressions in rule files",
		Long: `Update regular expressions in rule files.
This command will generate regulare expressions from the data
files and update the associated rule.

RULE_ID is the ID of the rule, e.g., 932100, or the regex-assembly file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.`,
		Args: cobra.MatchAll(cobra.MaximumNArgs(1), func(cmd *cobra.Command, args []string) error {
			allFlag := cmd.Flags().Lookup("all")
			if !allFlag.Changed && len(args) == 0 {
				return errors.New("expected either RULE_ID or flag, found neither")
			} else if allFlag.Changed && len(args) > 0 {
				return errors.New("expected either RULE_ID or flag, found both")
			}
			return nil
		}),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			err := parseRuleId(args[0])
			if err != nil {
				cmd.PrintErrf("failed to parse the rule ID from the input '%s'\n", args[0])
				return err
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
			ctxt := processors.NewContext(rootContext)
			processAll, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read value for 'all' flag")
			}
			performUpdate(processAll, ctxt)
		},
	}

}

func buildUpdateCommand() {
	regexCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolP("all", "a", false, `Instead of supplying a RULE_ID, you can tell the script to
update all rules from their regex-assembly files`)
}

func rebuildUpdateCommand() {
	if updateCmd != nil {
		updateCmd.Parent().RemoveCommand(updateCmd)
	}

	updateCmd = createUpdateCommand()
	buildUpdateCommand()
}

func performUpdate(processAll bool, ctx *processors.Context) {
	if processAll {
		err := filepath.WalkDir(ctx.RootContext().AssemblyDir(), func(filePath string, dirEntry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				// fail
				return err
			}

			if !dirEntry.IsDir() && path.Ext(dirEntry.Name()) == ".ra" {
				subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(dirEntry.Name(), -1)
				if subs == nil {
					// continue
					return nil
				}

				id := subs[0][1]
				chainOffsetString := subs[0][2]

				chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
				if err != nil && len(chainOffsetString) > 0 {
					return errors.New("failed to match chain offset. Value must not be larger than 255")
				}

				processRule(id, uint8(chainOffset), filePath, ctx)
				return nil
			}
			return nil
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to perform rule update(s)")
		}
	} else {
		filePath := path.Join(ctx.RootContext().AssemblyDir(), ruleValues.fileName)
		processRule(ruleValues.id, ruleValues.chainOffset, filePath, ctx)
	}
}

func runAssemble(filePath string) string {
	rootContext := context.New(rootValues.workingDirectory.String(), rootValues.configurationFileName.String())
	ctxt := processors.NewContext(rootContext)
	assembler := operators.NewAssembler(ctxt)
	var input []byte
	var err error
	if ruleValues.useStdin {
		logger.Trace().Msg("Reading from stdin")
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to read from stdin")
		}
	} else {
		logger.Trace().Msgf("Reading from %s", filePath)
		input, err = os.ReadFile(filePath)
		if err != nil {
			logger.Fatal().Err(err).Msgf("Failed to read regex-assembly file %s", filePath)
		}
	}
	assembly, err := assembler.Run(string(input))
	if err != nil {
		logger.Fatal().Err(err).Send()
	}
	return assembly
}

func processRule(ruleId string, chainOffset uint8, dataFilePath string, ctxt *processors.Context) {
	logger.Info().Msgf("Processing %s, chain offset %d", ruleId, chainOffset)
	regex := runAssemble(dataFilePath)

	rulePrefix := ruleId[:3]
	matches, err := filepath.Glob(fmt.Sprintf("%s/*-%s-*", ctxt.RootContext().RulesDir(), rulePrefix))
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to find rule file for rule id %s", ruleId)
	}
	if matches == nil || len(matches) > 1 {
		logger.Fatal().Msgf("Failed to find rule file for rule id %s", ruleId)
	}

	ruleFilePath := matches[0]
	logger.Debug().Msgf("Processing rule file %s for rule %s", ruleFilePath, ruleId)

	updateRegex(ruleFilePath, ruleId, chainOffset, regex)
}

func updateRegex(filePath string, ruleId string, chainOffset uint8, newRegex string) {
	contents, err := os.ReadFile(filePath)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to read rule file %s", filePath)
	}

	lines := bytes.Split(contents, []byte("\n"))

	idRegex := regexp.MustCompile(fmt.Sprintf("id:%s", ruleId))
	index := 0
	var line []byte
	foundRule := false
	chainCount := uint8(0)
	for index, line = range lines {
		if !foundRule && idRegex.Match(line) {
			foundRule = true
			if chainOffset == 0 {
				index--
				break
			}
			continue
		}
		if foundRule && regex.SecRuleRegex.Match(line) {
			chainCount++
		}
		if foundRule && chainCount == chainOffset {
			break
		}
	}
	if !foundRule || chainOffset != chainCount {
		logger.Fatal().Msgf("Failed to find rule %s, chain offset, %d in %s", ruleId, chainOffset, filePath)
	}

	regexLine := lines[index]
	found := regex.RuleRxRegex.FindAllStringSubmatch(string(regexLine), -1)
	if len(found) == 0 {
		logger.Fatal().Msgf("Failed to find rule %s in %s", ruleId, filePath)
	}
	updatedLine := found[0][1] + newRegex + found[0][3]
	lines[index] = []byte(updatedLine)

	err = os.WriteFile(filePath, bytes.Join(lines, []byte("\n")), fs.ModePerm)
	if err != nil {
		logger.Fatal().Err(err).Msgf("Failed to write rule file %s", filePath)
	}
}
