// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/crs-toolchain/v2/configuration"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/coreruleset/crs-toolchain/v2/regex/processors"
)

type assemblerTestSuite struct {
	suite.Suite
	ctx     *processors.Context
	tempDir string
}

type fileFormatTestSuite assemblerTestSuite
type specialCommentsTestSuite assemblerTestSuite
type specialCasesTestSuite assemblerTestSuite
type preprocessorsTestSuite assemblerTestSuite
type definitionsTestSuite assemblerTestSuite

func TestRunAssemblerTestSuite(t *testing.T) {
	suite.Run(t, new(fileFormatTestSuite))
	suite.Run(t, new(assemblerTestSuite))
	suite.Run(t, new(specialCommentsTestSuite))
	suite.Run(t, new(specialCasesTestSuite))
	suite.Run(t, new(preprocessorsTestSuite))
	suite.Run(t, new(definitionsTestSuite))
}

func (s *assemblerTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "assemble-test")
	s.Require().NoError(err)
	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *assemblerTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *fileFormatTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "file-format-test")
	s.Require().NoError(err)
	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *fileFormatTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *specialCommentsTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-comments-test")
	s.Require().NoError(err)
	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *specialCommentsTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *specialCasesTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "special-cases-test")
	s.Require().NoError(err)
	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *specialCasesTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *definitionsTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "definitions-test")
	s.Require().NoError(err)
	rootContext := context.New(s.tempDir, "toolchain.yaml")
	s.ctx = processors.NewContext(rootContext)
}

func (s *definitionsTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *preprocessorsTestSuite) SetupSuite() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "preprocessor-test")
	s.Require().NoError(err)

	rootContext := context.NewWithConfiguration(s.tempDir, s.newTestConfiguration())
	s.ctx = processors.NewContext(rootContext)
}

func (s *preprocessorsTestSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err)
}

func (s *preprocessorsTestSuite) newTestConfiguration() *configuration.Configuration {
	return &configuration.Configuration{
		Patterns: configuration.Patterns{
			AntiEvasion: configuration.Pattern{
				Unix:    "_av-u_",
				Windows: "_av-w_",
			},
			AntiEvasionSuffix: configuration.Pattern{
				Unix:    "_av-u-suffix_",
				Windows: "_av-w-suffix_",
			},
			AntiEvasionNoSpaceSuffix: configuration.Pattern{
				Unix:    "_av-ns-u-suffix_",
				Windows: "_av-ns-w-suffix_",
			},
		},
	}
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresSimpleComments() {
	contents := `##!line1
##!
##! line2
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotIgnoreSpecialComments() {
	contents := `##!+i
##!+ s
##!^prefix
##!^ prefix
##!$suffix
##!$ suffix
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("(?is)prefixprefixsuffixsuffix", output)

}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireCommentsToStartLine() {
	contents := `##!line1
##! line2
 not blank ##!+is 
		##!foo
	 ##! bar
##!\tline3
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Len(output, 17)
	s.Equal(`not blank ##!+is `, output)
}

func (s *fileFormatTestSuite) TestPreprocessHandlesPreprocessorComments() {
	contents := `##!> assemble`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Error(err)
	s.Empty(output)
}

func (s *fileFormatTestSuite) TestPreprocessIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)

	expected := "(?:some|another) line"
	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(expected, output)
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooManyEndMarkers() {
	contents := `##!> assemble
##!> assemble
##!<
##!<
##!<
`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Run(contents)
	s.EqualError(err, "stack is empty", "stack is not empty")
}

func (s *fileFormatTestSuite) TestPreprocessFailsOnTooFewEndMarkers() {
	contents := `##!> assemble
##!> assemble`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Run(contents)
	s.EqualError(err, "stack has unprocessed items", "stack is empty")
}

func (s *fileFormatTestSuite) TestPreprocessDoesNotRequireFinalEndMarker() {
	contents := `##!> assemble
##!> assemble
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Error(err)
	s.Empty(output)
}

func (s *specialCommentsTestSuite) TestHandlesIgnoreCaseFlag() {
	for _, contents := range []string{"##!+i\na", "##!+ i\na", "##!+   i\na"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(contents)
		s.Require().NoError(err)
		s.Equal("(?i)a", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesSingleLineFlag() {
	for _, contents := range []string{"##!+s\na", "##!+ s\na", "##!+   s\na"} {
		assembler := NewAssembler(s.ctx)
		output, err := assembler.Run(contents)
		s.Require().NoError(err)
		s.Equal("(?s)a", output)
	}
}

func (s *specialCommentsTestSuite) TestHandlesNoOtherFlags() {
	contents := "##!+mx"
	assembler := NewAssembler(s.ctx)

	s.PanicsWithValue("flag 'm' is not supported", func() { _, _ = assembler.Run(contents) }, "should panic because flags are not supported")
}

func (s *specialCommentsTestSuite) TestHandlesPrefixComment() {
	contents := `##!^ a prefix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal("a prefix[ab]", output)
}

func (s *specialCommentsTestSuite) TestHandlesSuffixComment() {
	contents := `##!$ a suffix
a
b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal("[ab]a suffix", output)
}

func (s *specialCasesTestSuite) TestIgnoresEmptyLines() {
	contents := `some line

another line`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal("(?:some|another) line", output)
}

func (s *specialCasesTestSuite) TestReturnsNoOutputForEmptyInput() {
	contents := `##!+ i

`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Empty(output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesBackslashEscapeCorrectly() {
	contents := `\x5c\x5ca`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`\x5c\x5ca`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapes() {
	contents := `a\x5c\x48\\x48b`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`a\x5cH\x5cx48b`, output)
}

func (s *specialCasesTestSuite) TestDoesNotDestroyHexEscapesInAlternations() {
	contents := `a\x5c\x48
b\x5c\x48
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`[ab]\x5cH`, output)
}

func (s *specialCasesTestSuite) TestSpecialComments_HandlesEscapedAlternationsCorrectly() {
	contents := `\|\|something|or other`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`\|\|something|or other`, output)
}

func (s *specialCasesTestSuite) TestAlwaysEscapesDoubleQuotes() {
	contents := `(?:"\"\\"a)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`\"\"\x5c"a`, output)
}

func (s *specialCasesTestSuite) TestDoesNotConvertHexEscapesOfNonPrintableCharacters() {
	contents := `(?:\x48\xe2\x93\xab)`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`H\xe2\x93\xab`, output)
}

func (s *specialCasesTestSuite) TestBackslashSReplacesPerlEquivalentCharacterClass() {
	// rassemble-go returns `[\t-\n\f-\r ]` for `\s`, which is correct for Perl
	// but does not include `\v`, which `\s` does in PCRE (3 and 2).
	contents := `\s`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`[\s\x0b]`, output)
}

func (s *preprocessorsTestSuite) TestSequentialPreprocessors() {
	contents := `##!> cmdline unix
foo
##!<
##!> cmdline windows
bar
##!<
##!> assemble
one
two
three
##!<
four
five
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`f(?:_av-u_o_av-u_o|our|ive)|b_av-w_a_av-w_r|one|t(?:wo|hree)`, output)
}

func (s *preprocessorsTestSuite) TestNestedPreprocessors() {
	contents := `##!> assemble
    ##!> cmdline unix
foo
    ##!<
    ##!> cmdline windows
bar
    ##!<
##!<
four
five
`
	assembler := NewAssembler(s.ctx)
	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`f(?:_av-u_o_av-u_o|our|ive)|b_av-w_a_av-w_r`, output)
}

func (s *preprocessorsTestSuite) TestComplexNestedPreprocessors() {
	contents := `##!> assemble
    ##!> cmdline unix
foo
    ##!<
  ##!=>
    ##!> assemble
ab
cd
    ##!<
    ##!> cmdline windows
bar
    ##!<
##!<
four
five
##!> assemble
six
seven
##!<
eight
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`f(?:_av-u_o_av-u_o(?:ab|cd|b_av-w_a_av-w_r)|our|ive)|s(?:ix|even)|eight`, output)
}

func (s *definitionsTestSuite) TestDefinition_ReplacesDefinition() {
	contents := `##!> define id __replaced__
{{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal("__replaced__", output)
}

func (s *definitionsTestSuite) TesDefinition_ReplacesMultipleDefinitions() {
	contents := `##!> define id __replaced__
some
{{id}}
other
{{id}}
##! lines
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal("some|__replaced__|other", output)
}

func (s *definitionsTestSuite) TestDefinition_IgnoresComments() {
	contents := `##!> define id __replaced__
##! {{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal("", output)
}

func (s *definitionsTestSuite) TestDefinition_ReplacesMultiplePerLine() {
	contents := `##!> define id __replaced__
{{id}}some{{id}}other{{id}}
##! lines
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal("__replaced__some__replaced__other__replaced__", output)
}

func (s *definitionsTestSuite) TestDefinition_RetainsEscapes() {
	contents := `##!> define id \n\s\b\v\t
{{id}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`\n[\s\x0b]\b\v\t`, output)

}

func (s *definitionsTestSuite) TestDefinition_ReplacseOnlySpecifiedDefinition() {
	contents := `##!> define slashes [/\\]
regex with {{slashes}} and {{dots}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`regex with [/\x5c] and \{\{dots\}\}`, output)
}

func (s *definitionsTestSuite) TestDefinition_ReplacesAllNormalOrder() {
	contents := `##!> define slashes [/\\]
##!> define dots [.,;]
regex with {{slashes}} and {{dots}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`regex with [/\x5c] and [,\.;]`, output)
}

func (s *definitionsTestSuite) TestDefinition_ReplacesAllInverseOrder() {
	contents := `##!> define slashes [/\\]
##!> define dots [.,;]
regex with {{dots}} and {{slashes}}
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`regex with [,\.;] and [/\x5c]`, output)
}

func (s *definitionsTestSuite) TestDefinition_ReplacseOnAllLines() {
	contents := `##!> define slashes [/\\]
##!> define dots [.,;]
##!> define other {{slashes}}+
{{slashes}}
##!=>
{{dots}}
##!=>
regex with {{slashes}} and {{dots}}
##!=>
{{other}}
##!=>
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`[/\x5c][,\.;]regex with [/\x5c] and [,\.;][/\x5c]+`, output)
}

func (s *assemblerTestSuite) TestAssemble_Assembling_1() {
	contents := `##!^ \W*\(
##!^ two
a+b|c
d
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`[^0-9A-Z_a-z]*\(two(?:a+b|[cd])`, output)

}

func (s *assemblerTestSuite) TestAssemble_Assembling_2() {
	contents := `##!$ \W*\(
##!$ two
a+b|c
d
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`(?:a+b|[cd])[^0-9A-Z_a-z]*\(two`, output)

}
func (s *assemblerTestSuite) TestAssemble_Assembling_3() {
	contents := `##!> assemble
line1
##!=>
  ##!> assemble
ab
cd
  ##!<
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal(`line1(?:ab|cd)`, output)

}
func (s *assemblerTestSuite) TestAssemble_Assembling_4() {
	contents := `##!> assemble
ab
##!=< myinput
##!<
##!> assemble
##!=> myinput
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)
	s.Equal("ab", output)

}
func (s *assemblerTestSuite) TestAssemble_Concatenating() {
	contents := `##!> assemble
one
two
##!=>
three
four
##!<
five
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`(?:one|two)(?:three|four)|five`, output)

}
func (s *assemblerTestSuite) TestAssemble_ConcatenatingMultipleSegments() {
	contents := `##!> assemble
one
two
##!=>
three
four
##!=>
five
##!=>
  ##!> assemble
six
seven
  ##!=>
eight
nine
  ##!<
##!=>
ten
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`(?:one|two)(?:three|four)fives(?:ix|even)(?:eight|nine)ten`, output)

}
func (s *assemblerTestSuite) TestAssemble_ConcatenatingMultipleSegments_() {
	contents := `##!> assemble
one
two
##!=>
three
four
##!=>
five
##!=>
  ##!> assemble
six
seven
  ##!=>
eight
nine
  ##!<
ten
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`(?:one|two)(?:three|four)five(?:s(?:ix|even)(?:eight|nine)|ten)`, output)

}

func (s *assemblerTestSuite) TestAssemble_ConcatenatingWithStoredInput() {
	contents := `##!> assemble
##! slash patterns
\x5c
##! URI encoded
%2f
%5c
##!=< slashes
##!=> slashes

##! dot patterns
\.
\.%00
\.%01
##!=>
##!=> slashes
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`(?:\x5c|%(?:2f|5c))\.(?:%0[01])?(?:\x5c|%(?:2f|5c))`, output)

}

func (s *assemblerTestSuite) TestAssemble_StoredInputIsGlobal() {
	contents := `##!> assemble
ab
cd
##!=< globalinput1
##!<

##!> assemble
##!=> globalinput1
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`ab|cd`, output)

}

func (s *assemblerTestSuite) TestAssemble_StoredInputIsAvailableToInnerScope() {
	contents := `##!> assemble
ab
cd
##!=< globalinput2
    ##!> assemble
    ##!=> globalinput2
    ##!<
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal("ab|cd", output)
}

func (s *assemblerTestSuite) TestAssemble_StoredInputIsAvailableToOuterScope() {
	contents := `##!> assemble
  ##!> assemble
ab
cd
  ##!=< globalinput
  ##!<
##!=> globalinput
##!<
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`ab|cd`, output)

}

func (s *assemblerTestSuite) TestAssemble_ConcatenatingFailsWhenInputUnknown() {
	contents := `##!> assemble
##!=> unknown
##!<
`
	assembler := NewAssembler(s.ctx)

	_, err := assembler.Run(contents)
	s.EqualError(err, "no entry in the stash for name 'unknown'")

}
func (s *assemblerTestSuite) TestAssemble_StoringAlternationAndConcatenation() {
	contents := `##!> assemble
  ##!> assemble
a
b
  ##!=>
c
d
  ##!=< input
  ##!<
  ##!<
##!=> input
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`[ab][cd]`, output)

}
func (s *assemblerTestSuite) TestAssemble_ConcatenationWithPrefixAndSuffix() {
	contents := `##!^ prefix
##!$ suffix
  ##!> assemble
a
b
  ##!=< input
  ##!<
##!=> input
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`prefix[ab]suffix`, output)

}
func (s *assemblerTestSuite) TestAssemble_AssembleWrappedInGroupWithTailConcatenation() {
	contents := `##!> assemble
a
b
  ##!=>
c
d
  ##!<
##!=>
more
##!=>
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`[ab][cd]more`, output)

}
func (s *assemblerTestSuite) TestAssemble_AssembleWrappedInGroupWithTailAlternation() {
	contents := `##!> assemble
a
b
  ##!=>
c
d
  ##!<
more
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`[ab][cd]|more`, output)

}
func (s *assemblerTestSuite) TestAssemble_NestedGroups() {
	contents := `(?:(?:x))+
prefix(?:(?:y))+
`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`x+|prefixy+`, output)

}
func (s *assemblerTestSuite) TestAssemble_RemoveExtraGroups() {
	contents := `(?:(?:a(?:b|c)(?:(?:d))))`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)
	s.Require().NoError(err)

	s.Equal(`a[bc]d`, output)
}

// The Go regexp/syntax library will convert a dot (`.`) into `(?-s:.)`.
// We want to retain the original dot.
func (s *assemblerTestSuite) TestAssemble_DotRemainsDot() {
	contents := "a.b"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("a.b", output)
}

// The Go regexp/syntax library will convert a dot (`.`) into `(?s:.)`.
// We want to retain the original dot.
func (s *assemblerTestSuite) TestAssemble_DotRemainsDotWithSflag() {
	contents := "##!+ s\na.b"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("(?s)a.b", output)
}

// The Go regexp/syntax library will convert a caret (`^`) into `(?m:^)`.
// We want to retain the original without the flag.
func (s *assemblerTestSuite) TestAssemble_CaretRemainsCaret() {
	contents := "^a|b"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("^a|b", output)
}

// The Go regexp/syntax library will convert a caret (`^`) into `(?m:^)`.
// We want to retain the original dot.
func (s *assemblerTestSuite) TestAssemble_CaretRemainsCaretWithSflag() {
	contents := "##!+ s\n^a|b"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("(?s)^a|b", output)
}

// The Go regexp/syntax library will convert a dollar (`$`) into `(?m:$)`.
// We want to retain the original dot.
func (s *assemblerTestSuite) TestAssemble_DollarRemainsDollar() {
	contents := "a|b$"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("a|b$", output)
}

// The Go regexp/syntax library will convert a dollar (`$`) into `(?m:$)`.
// We want to retain the original dot.
func (s *assemblerTestSuite) TestAssemble_DollarRemainsDollarWithSflag() {
	contents := "##!+ s\na|b$"
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("(?s)a|b$", output)
}

func (s *assemblerTestSuite) TestAssemble_ComplexAppendWithAlternation() {
	contents := `##!> assemble
  _prop-start_
  ##!=< js-prop-start
##!<

##!> assemble
  _prop-finish_
  ##!=< js-prop-finish
##!<


##!> assemble
  access
  ##!=< process-funcs
##!<

##!> assemble
  env
  ##!=< process-props
##!<

##! "process" payloads
##!> assemble
  process
  ##!=>

  ##!> assemble
    ##!=> js-prop-start
    ##!> assemble
	##!=> process-funcs
    ##!<
    ##!> assemble
      ##!=> process-props
    ##!<
    ##!=> js-prop-finish
  ##!<
##!<`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal("process_prop-start_(?:access|env)_prop-finish_", output)
}

func (s *assemblerTestSuite) TestAssemble_FlagGroupReplacementWithEscapedParentheses() {
	contents := `^\)ab\(c(capture)`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(contents, output)
}

// regexp/syntax procudes flag groups we don't want. Make sure that
// Removal of those groups does not remove groups that are semantically
// relevant, which is the case when the flag group wraps an alternation.
func (s *assemblerTestSuite) TestAssemble_ReplaceFlagGroupsWithAlternations() {
	contents := `(?-s:(?s:.)(?i:A|B .))`
	expected := `.(?:A|B .)`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(expected, output)
}

func (s *assemblerTestSuite) TestAssemble_RemoveOutermostNonMatchingGroup() {
	contents := `(?:ab|cd)`
	expected := `ab|cd`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(expected, output)
}
func (s *assemblerTestSuite) TestAssemble_RemoveOutermostNonMatchingGroup_WithExtraGroup() {
	contents := `(?:(?:ab|cd))`
	expected := `ab|cd`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(expected, output)
}

func (s *assemblerTestSuite) TestAssemble_RemoveOutermostNonMatchingGroup_Dont() {
	contents := `(?:ab|cd)e|fg`
	assembler := NewAssembler(s.ctx)

	output, err := assembler.Run(contents)

	s.Require().NoError(err)
	s.Equal(contents, output)
}
