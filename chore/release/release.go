package chore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cli/go-gh/v2/pkg/api"
	copyright "github.com/coreruleset/crs-toolchain/v2/chore/update_copyright"
	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"
)

var logger = log.With().Str("component", "release").Logger()

func Release(context *context.Context, repositoryPath string, version *semver.Version, sourceRef string) {
	branchName := fmt.Sprintf("v%d.%d.%d", version.Major(), version.Minor(), version.Patch())
	createAndCheckOutBranch(context, branchName, sourceRef)
	copyright.UpdateCopyright(context, version, uint16(time.Now().Year()))
	createCommit(context, branchName)
	pushBranch(branchName)
	createPullRequest(version, branchName, sourceRef)
}

func createAndCheckOutBranch(context *context.Context, branchName string, sourceRef string) {
	if err := checkForCleanWorkTree(context); err != nil {
		// FIXME
		panic(err)
	}

	out, err := runGit(context.RootDir(), "switch", "-c", branchName, sourceRef)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out).Msg("failed to create commit for release")
	}
}

func createCommit(context *context.Context, branchName string) {
	out, err := runGit(context.RootDir(), "commit", "-am", "Release "+branchName)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out).Msg("failed to create commit for release")
	}
}

func checkForCleanWorkTree(context *context.Context) error {
	repositoryPath := context.RootDir()
	repo, err := git.PlainOpen(repositoryPath)
	if err != nil {
		//FIXME
		panic(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		//FIXME
		panic(err)
	}
	status, err := worktree.Status()
	if err != nil {
		//FIXME
		panic(err)
	}
	if !status.IsClean() {
		// FIXME
		return errors.New("worktree not clean. Please stash or commit your changes first")
	}
	return nil
}

func createPullRequest(version *semver.Version, branchName string, targetBranchName string) {
	opts := api.ClientOptions{
		Headers: map[string]string{"Accept": "application/octet-stream"},
	}
	client, err := api.NewRESTClient(opts)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	type prBody struct {
		Title string `json:"title"`
		Head  string `json:"head"`
		Base  string `json:"base"`
	}
	bodyJson, err := json.Marshal(&prBody{
		Title: fmt.Sprintf("Release v%d.%d%d", version.Major(), version.Minor(), version.Patch()),
		Head:  "coreruleset:" + branchName,
		Base:  targetBranchName,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to serialize body of GH REST request")
	}

	response, err := client.Request(http.MethodPost, "repos/coreruleset/coreruleset/pulls", bytes.NewReader(bodyJson))
	if err != nil {
		log.Fatal().Err(err).Msg("Creating PR failed")
	}
	defer response.Body.Close()
}

func pushBranch(branchName string) {
	out, err := runGit("remote", "-v")
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out)
	}
	var remoteName string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "coreruleset/coreruleset") {
			remoteName = strings.Split(line, " ")[0]
		}
	}
	if remoteName == "" {
		logger.Fatal().Msg("failed to find remote to push release branch to")
	}

	out, err = runGit("push", remoteName, branchName)
	if err != nil {
		logger.Fatal().Err(err).Bytes("command-output", out)
	}
}

func runGit(repositoryPath string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repositoryPath
	return cmd.CombinedOutput()
}
