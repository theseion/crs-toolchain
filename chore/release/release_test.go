package chore

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/coreruleset/crs-toolchain/v2/context"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/suite"
)

type choreReleaseTestSuite struct {
	suite.Suite
	repoDir string
}

func (s *choreReleaseTestSuite) SetupTest() {
	s.repoDir = s.T().TempDir()
	cmd := exec.Command("git", "init", "-b", "main")
	cmd.Dir = s.repoDir
	err := cmd.Run()
	s.Require().NoError(err)

	cmd = exec.Command("git", "commit", "--allow-empty", "-m", "dummy")
	cmd.Dir = s.repoDir
	err = cmd.Run()
	s.Require().NoError(err)
}

func TestRunChoreReleaseTestSuite(t *testing.T) {
	suite.Run(t, new(choreReleaseTestSuite))
}

func (s *choreReleaseTestSuite) TestCreateAndcheckoutBranch() {
	branchName := "v1.2.3"
	ctxt := context.New(s.repoDir, "")
	createAndCheckOutBranch(ctxt, branchName, "main")
	repo, err := git.PlainOpen(s.repoDir)
	s.Require().NoError(err)

	branches, err := repo.Branches()
	s.Require().NoError(err)

	found := false
	var branchRef *plumbing.Reference
	branches.ForEach(func(r *plumbing.Reference) error {
		if r.Name().Short() == branchName {
			found = true
			branchRef = r
		}
		return nil
	})
	s.True(found)

	headRef, err := repo.Head()
	s.Require().NoError(err)

	s.Equal(branchRef.Hash(), headRef.Hash(), "New branch should have been checked out")
}

func (s *choreReleaseTestSuite) TestCreateCommit() {
	branchName := "v1.2.3"
	ctxt := context.New(s.repoDir, "")
	createAndCheckOutBranch(ctxt, branchName, "main")

	// Add something to commit, as `createCommit` doesn't allow empty commits
	os.WriteFile(path.Join(s.repoDir, "file"), []byte("content"), os.ModePerm)
	cmd := exec.Command("git", "add", ".")
	cmd.Dir = s.repoDir
	err := cmd.Run()
	s.Require().NoError(err)

	createCommit(ctxt, branchName)

	repo, err := git.PlainOpen(s.repoDir)
	s.Require().NoError(err)
	worktree, err := repo.Worktree()
	s.Require().NoError(err)
	status, err := worktree.Status()
	s.Require().NoError(err)
	s.True(status.IsClean())

	// HEAD has the new commit message
	revision, err := repo.ResolveRevision("HEAD")
	s.Require().NoError(err)
	commit, err := repo.CommitObject(*revision)
	s.Require().NoError(err)
	s.Equal(fmt.Sprintf("Release %s\n", branchName), commit.Message)

	// parent of HEAD is main
	parent, err := commit.Parent(0)
	s.Require().NoError(err)
	branchHash, err := repo.ResolveRevision(plumbing.Revision("main"))
	s.Require().NoError(err)
	s.Equal(*branchHash, parent.Hash)
}
