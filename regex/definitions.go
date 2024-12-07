// Copyright 2022 OWASP Core Rule Set Project
// SPDX-License-Identifier: Apache-2.0

package regex

import "regexp"

// IncludeRegex matches an include processor line (##! include <value>).
// The value is captured in group 1.
var IncludeRegex = regexp.MustCompile(`##!>\s*include\s+(\S+)(?:\s*--\s*(.*?))?\s*$`)

// IncludeExceptRegex matches an include-except processor line (##! include-except <value1> <value2>).
// The first value is captured in group 1, the second in group 2.
var IncludeExceptRegex = regexp.MustCompile(`^##!>\s*include-except\s+(\S+)\s*(.*?)(?:\s*--\s*(.*?))?\s*$`)

// DefinitionRegex matches a definition processor line (##! define <name> <value>)
// Everything up to the value of the definition is captured in group 1.
// The name is captured in group 2, the value in group 3.
var DefinitionRegex = regexp.MustCompile(`^(##!>\s*define\s+([a-zA-Z0-9-_]+)\s+)(\S+)\s*$`)

// CommentRegex matches a comment line (##!, no other directives)
var CommentRegex = regexp.MustCompile(`^\s*##!(?:[^^$+><=]|$)`)

// FlagsRegex matches a flags line (##!+ <value>).
// The value is captured in group 1.
var FlagsRegex = regexp.MustCompile(`^##!\+\s*(.*\S)\s*$`)

// PrefixRegex matches a prefix line (##!^ <value>)
// The value is captured in group 1.
var PrefixRegex = regexp.MustCompile(`^##!\^\s*(.*\S)\s*$`)

// SuffixRegex matches a suffix line (##!$ <value>)
// The value is captured in group 1.
var SuffixRegex = regexp.MustCompile(`^##!\$\s*(.*\S)\s*$`)

// ProcessorStartRegex matches any processor start line (##! assemble, ##! define <name> <value>).
// The name is captured in group 1, the optional value in group 2.
var ProcessorStartRegex = regexp.MustCompile(`^##!>\s*([a-z]+)(?:\s+([a-z]+))?`)

// ProcessorBlockStartRegex matches any processor start line, where the processor has a body
// (##! assemble, ##! cmdline <value>).
// The name is captured in group 1, the optional value is captured in group 2.
var ProcessorBlockStartRegex = regexp.MustCompile(`^##!>\s*(assemble|cmdline)\s*(\S+)?`)

// ProcessorEndRegex matches a processor end line (##!<)
var ProcessorEndRegex = regexp.MustCompile(`^##!<`)

// AssembleInputRegex matches an input line of the assemble processor (##!=< <name>).
// The name is captured in group 1.
var AssembleInputRegex = regexp.MustCompile(`^\s*##!=<\s*(.*)$`)

// AssembleOutputRegex matches an output line of the assemble processor (##!=> <name>).
// The name is captured in group 1, the optional output in group 2.
var AssembleOutputRegex = regexp.MustCompile(`^\s*##!=>\s*(.*)$`)

// RuleRxRegex matches a full SecRule line with @rx.
// Everything up to the start of the regular expression is captured in group 1,
// the end of the line after the regular expression is captured in group 2.
var RuleRxRegex = regexp.MustCompile(`(.*"!?@rx )(.*)(" \\)`)

// SecRuleRegex matches any SecRule line.
var SecRuleRegex = regexp.MustCompile(`\s*SecRule`)

// RuleIdFileNameRegex matches the rule ID in a regex-assembly file name (<id>-<chain>.ra).
// The rule ID is captured in group 1, the optional chain offset in group2,
// and the optional extension in group 3.
var RuleIdFileNameRegex = regexp.MustCompile(`^(\d{6})(?:-chain(\d+))?(?:\.ra)?$`)

// RuleIdTestFileNameRegex matches the rule ID in a test file name (<id>.yaml).
// The rule ID is captured in group 1, the optional extension in group 2.
var RuleIdTestFileNameRegex = regexp.MustCompile(`^(\d{6})(?:\.ya?ml)?$`)

// TestIdRegex matches any test_id line in test YAML files (test_id: <ID>).
// Everything up to the value of the test ID is captured in group 1, test ID in group 2.
var TestIdRegex = regexp.MustCompile(`(.*test_id:)\s+(.*$)`)

// TestTitleRegex matches any test_title line in test YAML files (test_title: "<title>").
// Everything up to the value of the test title is captured in group 1, test title in group 2.
var TestTitleRegex = regexp.MustCompile(`(.*test_title:)\s+(.*$)`)

// DefinitionReferenceRegex matches any reference to a definition.
// The matched reference name will be captured in group 1.
var DefinitionReferenceRegex = regexp.MustCompile(`{{([a-zA-Z0-9-_]+)}}`)

// CRSVersionRegex matches the version contained on every rules file.
// The version declared on the file is captured in group 3.
var CRSVersionRegex = regexp.MustCompile(`^(# OWASP (ModSecurity Core Rule Set|CRS) ver\.)(.+)$`)

// ShortCRSVersionRegex matches CRS version variable set in the setup file.
// The version number is captured in group 2.
var ShortCRSVersionRegex = regexp.MustCompile(`(setvar:tx.crs_setup_version=)(\d+)`)

// CRSCopyrightYearRegex matches the version and year range of the copyright text in setup,
// setup example, and rule files.
// The matched end year of the copyright year range will be captured in group 2.
var CRSCopyrightYearRegex = regexp.MustCompile(`^(# Copyright \(c\) 2021-)(\d{4})( (Core Rule Set|CRS) project. All rights reserved.)$`)

// CRSYearSecRuleVerRegex matches the version in the SecRule part of the text, (e.g. ver:'OWASP_CRS/4.0.0')
// setup example, and rule files.
// The matched year will be captured in group 2.
var CRSYearSecRuleVerRegex = regexp.MustCompile(`(ver:'OWASP_CRS/)(\d+\.\d+\.\d+(-[a-z0-9-]+)?)`)

// CRSVersionComponentSignatureRegex matches the version in the SecComponentSignature part of the text, (e.g. OWASP_CRS/4.0.0-rc1)
// setup example, and rule files.
// The matched year will be captured in group 2.
var CRSVersionComponentSignatureRegex = regexp.MustCompile(`^(SecComponentSignature "OWASP_CRS/)(\d+\.\d+\.\d+(-[a-z0-9-]+)?)`)
