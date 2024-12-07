// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/regex"
)

// generateCmd represents the generate command
var regexCmd = createRegexCommand()
var ruleValues struct {
	id          string
	fileName    string
	chainOffset uint8
	useStdin    bool
}

func init() {
	buildRegexCommand()
}

func createRegexCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "regex",
		Short: "Commands that process regular expressions",
		Long: `The commands in this group all interact with regular expressions.
For example, they generate regular expressions from regex-assembly files, update regular expressions
in rule files, or compare the regular expressions in rule files against what would be
generated from the current regex-assembly file.`,
	}

}

func buildRegexCommand() {
	rootCmd.AddCommand(regexCmd)
}

func rebuildRegexCommand() {
	if regexCmd != nil {
		regexCmd.Parent().RemoveCommand(regexCmd)
		ruleValues.id = ""
		ruleValues.fileName = ""
		ruleValues.chainOffset = 0
		ruleValues.useStdin = false
	}

	generateCmd = createRegexCommand()
	buildRegexCommand()
}

func parseRuleId(idAndChainOffset string) error {
	ruleValues.useStdin = false

	subs := regex.RuleIdFileNameRegex.FindAllStringSubmatch(idAndChainOffset, -1)
	if subs == nil {
		return errors.New("failed to match rule ID")
	}

	fileName := subs[0][0]
	id := subs[0][1]
	chainOffsetString := subs[0][2]

	chainOffset, err := strconv.ParseUint(chainOffsetString, 10, 8)
	if err != nil && len(chainOffsetString) > 0 {
		return errors.New("failed to match chain offset. Value must not be larger than 255")
	}

	if !strings.HasSuffix(fileName, ".ra") {
		fileName += ".ra"
	}

	ruleValues.id = id
	ruleValues.fileName = fileName
	ruleValues.chainOffset = uint8(chainOffset)

	return nil
}
