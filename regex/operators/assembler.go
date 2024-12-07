// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/itchyny/rassemble-go"

	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/parser"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

// Create the processor stack
var processorStack ProcessorStack
var processor processors.IProcessor

// NewAssembler creates a new Operator based on context.
func NewAssembler(ctx *processors.Context) *Operator {
	return &Operator{
		name:                          "assemble",
		details:                       make(map[string]string),
		lines:                         []string{},
		ctx:                           ctx,
		stats:                         NewStats(),
		groupReplacementStringBuilder: &strings.Builder{},
	}
}

func (a *Operator) Run(input string) (string, error) {
	processorStack = NewProcessorStack()
	logger.Trace().Msg("Starting assembler")
	assembleParser := parser.NewParser(a.ctx, strings.NewReader(input))
	lines, _ := assembleParser.Parse(false)
	logger.Trace().Msgf("Parsed lines: %v", lines)
	assembled, err := a.assemble(assembleParser, lines)
	if err != nil {
		return "", err
	}
	if p, _ := processorStack.top(); p != nil {
		return assembled, errors.New("stack has unprocessed items")
	}
	return assembled, err
}

func (a *Operator) assemble(assembleParser *parser.Parser, input *bytes.Buffer) (string, error) {
	fileScanner := bufio.NewScanner(bytes.NewReader(input.Bytes()))
	fileScanner.Split(bufio.ScanLines)
	processor = processors.NewAssemble(a.ctx)
	processorStack.push(processor)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		logger.Trace().Msgf("parsing line: %q", line)

		if procline := regex.ProcessorStartRegex.FindStringSubmatch(line); len(procline) > 0 {
			if err := a.startPreprocessor(procline[1], procline[2:]); err != nil {
				return "", err
			}
		} else if regex.ProcessorEndRegex.MatchString(line) {
			lines, err := a.endPreprocessor()
			if err != nil {
				return "", err
			}
			if err = processor.Consume(lines); err != nil {
				return "", err
			}
		} else {
			logger.Trace().Msg("Processor is processing line")
			if err := processor.ProcessLine(line); err != nil {
				logger.Error().Err(err).Msgf("failed to process line %s", line)
				return "", err
			}
		}
	}

	processor, err := processorStack.top()
	if err != nil {
		logger.Error().Err(err).Msg("Mismatched end marker, processor stack is empty")
		return "", err
	}
	lines, err := processor.Complete()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to complete processor")
		return "", err
	}
	logger.Trace().Msgf("** Got lines from Processor: %v\n", lines)
	a.lines = append(a.lines, lines...)
	_, err = processorStack.pop()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to remove assembler processor.")
		return "", err
	}
	return a.complete(assembleParser), nil
}

func (a *Operator) complete(assembleParser *parser.Parser) string {
	logger.Trace().Msgf("** completing using: %v\n", a.lines)
	flagsPrefix := ""
	if len(assembleParser.Flags) > 0 {
		flags := make([]string, 0, len(assembleParser.Flags))
		for flag := range assembleParser.Flags {
			flags = append(flags, string(flag))
		}
		sort.Strings(flags)
		flagsPrefix = "(?" + strings.Join(flags, "") + ")"
	}

	logger.Trace().Msg("Final alternation pass")
	result, err := a.runFinalPass()
	if err != nil {
		logger.Fatal().Err(err).Msg("Final pass failed")
	}

	if len(assembleParser.Prefixes) > 0 && len(assembleParser.Suffixes) > 0 && len(result) > 0 {
		result = "(?:" + result + ")"
	}
	prefixes := strings.Join(assembleParser.Prefixes, "")
	suffixes := strings.Join(assembleParser.Suffixes, "")
	result = prefixes + result + suffixes

	if len(result) > 0 {
		logger.Trace().Msgf("Applying last cleanups to %s\n", result)
		result = a.runSimplificationAssembly(result)
		logger.Trace().Msgf("After simplification assembly: %s\n", result)
		result = a.useHexEscapes(result)
		logger.Trace().Msgf("After replacing non-printable characters with hex escapes: %s\n", result)
		result = a.escapeDoublequotes(result)
		logger.Trace().Msgf("After escaping double quotes: %s\n", result)
		result = a.useHexBackslashes(result)
		logger.Trace().Msgf("After replacing plain backslashes with hex escapes: %s\n", result)
		result = a.includeVerticalTabInSpaceClass(result)
		logger.Trace().Msgf("After including vertical tabs: %s\n", result)
		result = a.dontUseFlagsForMetaCharacters(result)
		logger.Trace().Msgf("After removing meta character flags: %s\n", result)
		result = a.removeOutermostNonCapturingGroup(result)
		logger.Trace().Msgf("After removing outermost non-capturing group: %s\n", result)
	}

	if len(flagsPrefix) > 0 && len(result) > 0 {
		result = flagsPrefix + result
	}

	return result
}

func (a *Operator) runFinalPass() (string, error) {
	processor := processors.NewAssemble(a.ctx)
	for _, line := range a.lines {
		if err := processor.ProcessLine(line); err != nil {
			logger.Error().Err(err).Msgf("failed to process line %s", line)
			return "", err
		}
	}
	result, err := processor.Complete()
	if err != nil {
		return "", err
	}
	return strings.Join(result, ""), nil
}

// Once the entire expression has been assembled, run one last
// pass to possibly simplify groups and concatenations.
func (a *Operator) runSimplificationAssembly(input string) string {
	logger.Trace().Msgf("Simplifying regex %s\n", input)
	result, err := rassemble.Join([]string{input})
	logger.Trace().Msgf("=> Simplified to %s\n", result)
	if err != nil {
		logger.Fatal().Err(err).Str("regex", input).Msg("Failed to simplify regex")
	}
	return result
}

// escapeDoublequotes takes a double quote and adds the `\` char before it.
// We need all double quotes to be escaped because we use them
// as delimiters in rules.
func (a *Operator) escapeDoublequotes(input string) string {
	logger.Trace().Msg("Escaping double quotes")
	binput := []byte(input)
	result := bytes.Buffer{}
	for k, v := range binput {
		if k == 0 && v == '"' {
			result.WriteString(`\"`)
		} else if k > 0 && v == '"' && binput[k-1] != '\\' {
			result.WriteString(`\"`)
		} else {
			result.WriteByte(v)
		}
	}
	return result.String()
}

// useHexBackslashes replaces all literal backslashes with `\x5c`,
// the hexadecimal representation of a backslash. This is for compatibility and
// readbility reasons, as Apache httpd handles sequences of backslashes
// differently than nginx.
func (a *Operator) useHexBackslashes(input string) string {
	return strings.ReplaceAll(input, `\\`, `\x5c`)
}

// In Perl, the vertical tab (`VT`, `\x0b`) is *not* part of `\s`, but it is
// in newer versions of PCRE (both 3 and 2) (`\v` in PCRE is actually
// a list of vertical characters, one of which is `VT`).
// Go's `regexp/syntax` package
// uses Perl as the reference and, hence, generates `[\t-\n\f-\r ]` as the
// character class for `\s`, i.e., `VT` is missing.
// We simply replace the generated class with `[\s\0xb]` to fix this.
// Note that we could use simply use  `\s` for PCRE, but this will not work
// for re2 compatible engines.
// Note also that we use the hex escape code for the vertical tab because in
// PCRE2 ranges in character classes are not allowed to start with escape codes
// that expand to multiple code points, which includes `\v`. In the original
// implementation of PCRE, `\v` was not illegal but led to the range token (`-`)
// to be interpreted as a literal.
func (a *Operator) includeVerticalTabInSpaceClass(input string) string {
	logger.Trace().Msg("Fixing up regex to include vertical tab (VT) in white space class matches")
	return strings.ReplaceAll(input, `\t\n\f\r `, `\s\x0b`)
}

// rassemble-go doesn't provide an option to specify literals.
// Go itself would, via the `Literal` flag to `syntax.Parse`.
// As it is, escapes that are printable runes will be returned as such,
// which means we will have weird looking characters in our regex
// instead of hex escapes.
// To replace the characters with their hex escape sequence, we can simply
// take the decimal value of each byte (this might be a single byte of a
// multi-byte sequnce), check whether it is a printable character and
// then either append it to the output string or create the equivalent
// escape code.
//
// Note: presumes that hexadecimal escapes in the input create UTF-8
// sequences.
//
// Note: not all hex escapes in the input will be escaped in the
// output, but all printable non-printable characters, including
// `\v\n\r` and space (`\x32`).
func (a *Operator) useHexEscapes(input string) string {
	var sb strings.Builder
	for _, char := range input {
		if char < 32 || char > 126 {
			sb.WriteString(`\x`)
			sb.WriteString(fmt.Sprintf("%x", char))
		} else {
			sb.WriteRune(char)
		}
	}
	return sb.String()
}

// The Go regexp/syntax library will convert insert flags when it encounters
// meta characters that could be ambiguous, such as `^`, `$`, `.`.
// Remove both flags for the current context, e.g., `...(?m)...`, and flag groups
// applied to subexpressions, e.g., `...(?m:...)...`
func (o *Operator) dontUseFlagsForMetaCharacters(input string) string {
	result := input
	flagsStartRegexp := regexp.MustCompile(`\(\?[-misU]+\)`)
	result = flagsStartRegexp.ReplaceAllLiteralString(result, "")

	flagGroupStartRegexp := regexp.MustCompile(`\(\?[-misU]+:`)
	for {
		location := flagGroupStartRegexp.FindStringIndex(result)
		if len(location) > 0 {
			result = o.removeGroup(result, location[0], location[1], false)
		} else {
			break
		}
	}
	return result
}

// Remove groups like `...(?-s:...)...`.
// If a group has an alternation on the same level as the group that
// should be replaced, the group needs to be retained in order to
// retain semantics, but the flags should still be removed.
// Ignore alternations if `ignoreAlternations` is true. This can be used
// to remove a top level group, in which case alternations with and without
// the group would be equivalent.
func (o *Operator) removeGroup(input string, groupStart int, bodyStart int, ignoreAlternations bool) string {
	bodyEnd, hasAlternation := o.findGroupBodyEnd(input, bodyStart)
	hasAlternation = hasAlternation && !ignoreAlternations

	o.groupReplacementStringBuilder.Reset()
	o.groupReplacementStringBuilder.WriteString(input[:groupStart])
	if hasAlternation {
		o.groupReplacementStringBuilder.WriteString("(?:")
	}
	o.groupReplacementStringBuilder.WriteString(input[bodyStart : bodyEnd+1])
	if hasAlternation {
		o.groupReplacementStringBuilder.WriteString(")")
	}
	o.groupReplacementStringBuilder.WriteString(input[bodyEnd+2:])
	return o.groupReplacementStringBuilder.String()
}

// Removes the topmost non-capturing group if it is redundant.
func (o *Operator) removeOutermostNonCapturingGroup(input string) string {
	matcher := regexp.MustCompile(`^\(\?:.*\)$`)
	if !matcher.MatchString(input) {
		return input
	}

	bodyEnd, _ := o.findGroupBodyEnd(input, 3)
	if bodyEnd+1 < len(input)-1 {
		return input
	}

	return o.removeGroup(input, 0, 3, true)
}

// Returns the index of the last token of the group whose body starts at
// `groupBodyStart`. Resturns `true`, as the second value, if the group
// has an alternation on the topmost level, `false` otherwise.
func (o *Operator) findGroupBodyEnd(input string, groupBodyStart int) (int, bool) {
	hasAlternation := false
	parensCounter := 1
	index := groupBodyStart
	for ; parensCounter > 0; index++ {
		char := input[index]
		switch char {
		case '(':
			if !isEscaped(input, index) {
				parensCounter++
			}
		case ')':
			if !isEscaped(input, index) {
				parensCounter--
			}
		case '|':
			if parensCounter == 1 {
				hasAlternation = true
			}
		}
	}

	return index - 2, hasAlternation
}

func isEscaped(input string, position int) bool {
	escapeCounter := 0
	for backtrackIndex := position - 1; backtrackIndex >= 0; backtrackIndex++ {
		if input[backtrackIndex] != '\\' {
			break
		}
		escapeCounter++
	}
	return escapeCounter%2 != 0
}

func (a *Operator) startPreprocessor(processorName string, args []string) error {
	logger.Trace().Msgf("Found processor %s start\n", processorName)
	switch processorName {
	case "assemble":
		assemble := processors.NewAssemble(a.ctx)
		processorStack.push(assemble)
		processor = assemble
	case "cmdline":
		cmdType, err := processors.CmdLineTypeFromString(args[0])
		if err != nil {
			logger.Error().Err(err).Msgf("Wrong cmdline type used: %s\n", args[0])
			return err
		}
		cmdline := processors.NewCmdLine(a.ctx, cmdType)
		processorStack.push(cmdline)
		processor = cmdline
	default:
		logger.Error().Msgf("Unknown processor name found: %s\n", processorName)
		return errors.New("unknown processor found")
	}
	return nil
}

func (a *Operator) endPreprocessor() ([]string, error) {
	logger.Trace().Msg("Found processor end")
	lines, err := processor.Complete()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to complete processor")
		return nil, err
	}
	logger.Trace().Msgf("** Got lines from Processor: %v\n", lines)
	// remove actual processor. read from top next processor.
	_, err = processorStack.pop()
	if err != nil {
		logger.Error().Err(err).Msg("Mismatched end marker, processor stack is empty")
		return nil, err
	}
	processor, err = processorStack.top()
	if err != nil {
		logger.Error().Err(err).Msg("Ooops, nothing on top, processor stack is empty")
		return nil, err
	}
	return lines, nil
}
