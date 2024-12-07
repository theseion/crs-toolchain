// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

// Package parser implements the parsing logic to obtain the sequence of inputs ready for processing.
// The two main thing it will do is to parse a regex-assembly file and recursively solve all `includes` first, then
// substitute all definitions where necessary.
package parser

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"dario.cat/mergo"
	"github.com/rs/zerolog/log"

	"github.com/coreruleset/crs-toolchain/v2/regex"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

var logger = log.With().Str("component", "parser").Logger()
var spaceRegex = regexp.MustCompile(`\s+`)

type parsedType int

const (
	includePatternName       string     = "include"
	includeExceptPatternName string     = "include-except"
	definitionPatternName    string     = "definition"
	commentPatternName       string     = "comment"
	flagsPatternName         string     = "flags"
	prefixPatternName        string     = "prefix"
	suffixPatternName        string     = "suffix"
	regular                  parsedType = iota
	empty
	include
	includeExcept
	definition
	comment
	flags
	prefix
	suffix
)

// Parser is the base parser type. It will provide processors with all the inclusions and definitions resolved.
type Parser struct {
	ctx       *processors.Context
	src       io.Reader
	dest      *bytes.Buffer
	variables map[string]string
	Flags     map[rune]bool
	Prefixes  []string
	Suffixes  []string
	patterns  map[string]*regexp.Regexp
}

// ParsedLine will store the results of parsing the line. `parsedType` will discriminate how you read the results:
// if the type is `include`, then the result map will store the file name in the "include" key. The definition type
// will just use the map for the name:value.
type ParsedLine struct {
	parsedType         parsedType
	line               string
	includeFileName    string
	excludeFileNames   []string
	suffixReplacements map[string]string
	definitions        map[string]string
	prefix             string
	suffix             string
	flags              string
}

// NewParser creates a new parser from an io.Reader.
func NewParser(ctx *processors.Context, reader io.Reader) *Parser {
	p := &Parser{
		ctx:       ctx,
		src:       reader,
		dest:      &bytes.Buffer{},
		variables: make(map[string]string),
		Flags:     make(map[rune]bool),
		Prefixes:  []string{},
		Suffixes:  []string{},
		patterns: map[string]*regexp.Regexp{
			includePatternName:       regex.IncludeRegex,
			includeExceptPatternName: regex.IncludeExceptRegex,
			definitionPatternName:    regex.DefinitionRegex,
			commentPatternName:       regex.CommentRegex,
			flagsPatternName:         regex.FlagsRegex,
			prefixPatternName:        regex.PrefixRegex,
			suffixPatternName:        regex.SuffixRegex,
		},
	}
	return p
}

// Parse does the parsing and returns a buffer with all the bytes to process or an error if the reader
// could not be parsed.
func (p *Parser) Parse(formatOnly bool) (*bytes.Buffer, int) {
	fileScanner := bufio.NewScanner(p.src)
	fileScanner.Split(bufio.ScanLines)
	wrote := 0
	var text string

	for fileScanner.Scan() {
		line := fileScanner.Text()
		// remove indentation
		line = strings.TrimLeft(line, " \t")
		text = "" // empty text each iteration
		logger.Trace().Msgf("parsing line: %q", line)
		parsedLine := p.parseLine(line)
		switch parsedLine.parsedType {
		case regular:
			text = line + "\n"
		// remove comments and empty lines from the parsed line
		case empty, comment:
		case definition:
			if !formatOnly {
				// merge maps p.variables and parsedLine.definitions
				err := mergo.Merge(&p.variables, parsedLine.definitions)
				if err != nil {
					logger.Error().Err(err).Msg("error merging definitions")
				}
			}
		case include:
			if !formatOnly {
				// go read the included file and paste text here
				var err error
				text, err = buildIncludeString(p, parsedLine)
				if err != nil {
					logger.Panic().Err(err).Msg("Failed to parse `include` directive")
				}
			}
		case includeExcept:
			if !formatOnly {
				// go read the included files but exclude exclusions
				var err error
				text, err = buildIncludeExceptString(p, parsedLine)
				if err != nil {
					logger.Panic().Err(err).Msg("Failed to parse `include-except` directive")
				}
			}
		case flags:
			for _, flag := range parsedLine.flags {
				if flagIsAllowed(flag) {
					p.Flags[flag] = true
				} else {
					logger.Panic().Msgf("flag '%s' is not supported", string(flag))
				}
			}
		case prefix:
			p.Prefixes = append(p.Prefixes, parsedLine.prefix)
		case suffix:
			p.Suffixes = append(p.Suffixes, parsedLine.suffix)
		}
		if formatOnly {
			text = line + "\n"
		} else if text == "" {
			continue
		}

		logger.Trace().Msgf("** ADDING text: %q", text)
		// err is always nil
		n, _ := p.dest.WriteString(text)
		wrote += n
	}

	// now that the file was parsed, we replace all definitions
	if len(p.variables) > 0 {
		p.dest = expandDefinitions(p.dest, p.variables)
	}
	return p.dest, wrote
}

// parseLine iterates over the pattern list and if found, creates the ParsedLine object with the results.
func (p *Parser) parseLine(line string) ParsedLine {
	pl := ParsedLine{
		parsedType: regular,
		line:       line,
	}
	if len(strings.TrimSpace(line)) == 0 {
		pl.parsedType = empty
		return pl
	}

	for name, pattern := range p.patterns {
		found := pattern.FindStringSubmatch(line)
		// found[0] has the whole line that matched, found[N] has the subgroup
		if len(found) > 0 {
			logger.Trace().Msgf("found %s statement: %v", name, found[0])
			switch name {
			case commentPatternName:
				pl.parsedType = comment
			case includePatternName:
				pl.parsedType = include
				pl.includeFileName = found[1]
				pl.suffixReplacements = buildPairMap(found[2])
			case includeExceptPatternName:
				pl.parsedType = includeExcept
				pl.includeFileName = found[1]
				pl.suffixReplacements = buildPairMap(found[3])
				pl.excludeFileNames = splitArgs(found[2])
			case definitionPatternName:
				pl.parsedType = definition
				pl.definitions = map[string]string{found[2]: found[3]}
			case flagsPatternName:
				pl.parsedType = flags
				pl.flags = found[1]
			case prefixPatternName:
				pl.parsedType = prefix
				pl.prefix = found[1]
			case suffixPatternName:
				pl.parsedType = suffix
				pl.suffix = found[1]
			}
			break
		}
	}
	return pl
}

func buildPairMap(input string) map[string]string {
	if len(strings.TrimSpace(input)) == 0 {
		return nil
	}

	logger.Trace().Msgf("Building pair map for: %s", input)
	list := splitArgs(input)
	if len(list)%2 > 0 {
		logger.Panic().Msgf("uneven number of arguments found: %s", input)
	}

	pairMap := map[string]string{}
	for i := 0; i < len(list); i += 2 {
		pairMap[list[i]] = list[i+1]
	}

	logger.Trace().Msgf("Built pair map: %v", pairMap)
	return pairMap
}

func splitArgs(input string) []string {
	cleanInput := spaceRegex.ReplaceAllString(input, " ")
	return strings.Split(cleanInput, " ")
}

// parseFile does just a new call to the Parser on the named file. It will use the context to find files that have relative filenames.
func parseFile(rootParser *Parser, filename string, definitions map[string]string) (*bytes.Buffer, map[string]string) {
	logger.Debug().Msgf("reading file: %v", filename)
	if path.Ext(filename) != ".ra" {
		filename += ".ra"
	}

	// check if filename has an absolute path
	// if it is relative, use the context to get the parent directory where we should search for the file.
	rootContext := rootParser.ctx.RootContext()
	var err error
	var readFile *os.File
	filePath := filename
	for _, directory := range []string{rootContext.IncludesDir(), rootContext.ExcludesDir()} {
		if !filepath.IsAbs(filename) {
			filePath = filepath.Join(directory, filename)
		}
		readFile, err = os.Open(filePath)
		if err == nil {
			break
		}
	}
	if err != nil {
		logger.Fatal().Msgf("cannot open file for parsing: %v", err.Error())
	}
	newP := NewParser(rootParser.ctx, bufio.NewReader(readFile))
	if definitions != nil {
		newP.variables = definitions
	}
	out, _ := newP.Parse(false)
	newOut, err := mergePrefixesSuffixes(rootParser, newP, out)
	if err != nil {
		logger.Fatal().Msgf("error parsing file: %v", err.Error())
	}
	logger.Trace().Msg(newOut.String())
	return newOut, newP.variables
}

// Merge prefixes, and suffixes from include files into another parser.
// All of these need to be treated as local to the source parser.
// We removed flag merging because of https://github.com/coreruleset/crs-toolchain/v2/issues/72
func mergePrefixesSuffixes(target *Parser, source *Parser, out *bytes.Buffer) (*bytes.Buffer, error) {
	logger.Trace().Msg("merging prefixes, suffixes from included file")
	// If the included file has flags, this is an error
	if len(source.Flags) > 0 {
		return new(bytes.Buffer), errors.New("include files must not contain flags. See https://github.com/coreruleset/crs-toolchain/v2/issues/71")
	}
	// IMPORTANT: don't write the assemble block at all if there are no flags, prefixes, or
	// suffixes. Enclosing the output in an assemble block can change the semantics, for example,
	// when the included content is processed by the cmdline processor in the including file.
	if len(source.Prefixes) == 0 && len(source.Suffixes) == 0 {
		return out, nil
	}

	newOut := new(bytes.Buffer)
	newOut.WriteString("##!> assemble\n")

	for _, prefix := range source.Prefixes {
		newOut.WriteString(prefix)
		newOut.WriteString("\n##!=>\n")
	}
	if _, err := out.WriteTo(newOut); err != nil {
		logger.Fatal().Err(err).Msg("failed to copy output to new buffer")
	}

	sawNewLine := false
	if err := out.UnreadByte(); err == nil {
		lastByte, err := out.ReadByte()
		if err == nil {
			sawNewLine = lastByte == 13
		}
	}
	if sawNewLine {
		newOut.WriteString("\n")
	}
	if len(source.Suffixes) > 0 {
		newOut.WriteString("##!=>\n")
	}
	for _, suffix := range source.Suffixes {
		newOut.WriteString(suffix)
		newOut.WriteString("\n##!=>\n")
	}
	newOut.WriteString("##!<\n")
	return newOut, nil
}

func expandDefinitions(src *bytes.Buffer, variables map[string]string) *bytes.Buffer {
	logger.Trace().Msgf("expanding definitions in: %v", src.String())
	// Definitions can contain definitions themeselves
	for needle, replacement := range variables {
		needle := "{{" + needle + "}}"
		for sourceName, source := range variables {
			variables[sourceName] = strings.ReplaceAll(source, needle, replacement)
		}
	}
	// Now replace definitions in the rest of the file
	for needle, replacement := range variables {
		needle := "{{" + needle + "}}"
		src = bytes.NewBuffer(bytes.ReplaceAll(src.Bytes(), []byte(needle), []byte(replacement)))
	}
	// After all replacements, check if we have dangling names around. They mean that no definition was created
	// yet, or there is a typo.
	dangling := regex.DefinitionReferenceRegex.FindSubmatch(src.Bytes())
	if dangling != nil {
		logger.Warn().Msgf("no match found for definition: {{%s}}. could be a typo, or you forgot to define it?", string(dangling[1]))
	}
	logger.Trace().Msgf("expanded all definitions in: %v", src.String())
	return src
}

func flagIsAllowed(flag rune) bool {
	allowed := false
	switch flag {
	case 'i', 's':
		allowed = true
	}
	return allowed
}
