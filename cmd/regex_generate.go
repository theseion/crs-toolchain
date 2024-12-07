// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"io"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/operators"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// generateCmd represents the generate command
var generateCmd = createGenerateCommand()

func init() {
	buildGenerateCommand()
}

func createGenerateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "generate RULE_ID | -",
		Short: "Generate regular expression from a regex-assembly file",
		Long: `Generate regular expression from a regex-assembly file.
This command is mainly used for quick debugging.
It prints the generated regular expression to stdout.

RULE_ID is the ID of the rule, e.g., 932100, or the regex-assembly file name.
If the rule is a chained rule, RULE_ID must be specified with the
offset of the chain from the chain starter rule. For example, to
generate a second level chained rule, RULE_ID would be 932100-chain2.

The special token '-' will cause the script to accept input
from stdin.`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no argument provided")
			}
			if args[0] == "-" {
				ruleValues.useStdin = true
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
				filePath := path.Join(ctxt.RootContext().AssemblyDir(), ruleValues.fileName)
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
			os.Stdout.WriteString(assembly)
		},
	}
}

func buildGenerateCommand() {
	regexCmd.AddCommand(generateCmd)
}

func rebuildGenerateCommand() {
	if generateCmd != nil {
		generateCmd.Parent().RemoveCommand(generateCmd)
	}

	generateCmd = createGenerateCommand()
	buildGenerateCommand()
}
