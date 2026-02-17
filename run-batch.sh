#!/bin/zsh
# run-batch.sh — Launch parallel Claude Code instances for Batch 1
#
# Usage: ./run-batch.sh
#
# Creates git worktrees and tmux windows for each task, then launches
# Claude Code interactively so you can watch live progress.

set -euo pipefail

REPO_DIR="$HOME/Projects/steward"
SESSION="steward-batch1"

# Batch 1 tasks (parallel arrays)
BRANCHES=("leak-detector" "ingress-sanitizer" "audit-logger" "permission-engine")
TASK_FILES=("TASK-1.1.md" "TASK-1.2.md" "TASK-1.3.md" "TASK-1.4.md")

# Ensure we're on latest main
cd "$REPO_DIR"
echo "Ensuring main is up to date..."
git checkout main
git pull origin main 2>/dev/null || true

# Create tmux session (detached)
echo "Creating tmux session: $SESSION"
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n "overview"

for i in {1..${#BRANCHES[@]}}; do
  branch="${BRANCHES[$i]}"
  task_file="${TASK_FILES[$i]}"
  wt_dir="${REPO_DIR}-wt-${branch}"
  feat_branch="feat/${branch}"

  echo ""
  echo "=== Setting up ${feat_branch} ==="

  # Create worktree (remove stale one if exists)
  if [ -d "$wt_dir" ]; then
    echo "  Removing existing worktree at $wt_dir"
    git worktree remove "$wt_dir" --force 2>/dev/null || rm -rf "$wt_dir"
  fi

  # Delete branch if it exists locally (leftover from previous run)
  git branch -D "$feat_branch" 2>/dev/null || true

  echo "  Creating worktree: $wt_dir on $feat_branch"
  git worktree add "$wt_dir" -b "$feat_branch"

  # Create tmux window
  echo "  Creating tmux window: $branch"
  tmux new-window -t "$SESSION" -n "$branch"

  # Start claude interactively with restricted permissions (allow/deny from .claude/settings.json)
  tmux send-keys -t "$SESSION:$branch" "cd $wt_dir && claude --permission-mode dontAsk" Enter

  # Wait for claude to initialize
  sleep 3

  # Paste the task prompt into claude's input
  # Use tmux load-buffer to handle the long prompt content
  tmux load-buffer -b "task-${branch}" "${REPO_DIR}/docs/tasks/${task_file}"
  tmux paste-buffer -b "task-${branch}" -t "$SESSION:$branch"

  # Submit the prompt
  sleep 1
  tmux send-keys -t "$SESSION:$branch" Enter

  echo "  Launched Claude Code for $task_file"
done

echo ""
echo "================================================"
echo "  All 4 tasks launched in tmux session: $SESSION"
echo "================================================"
echo ""
echo "  tmux attach -t $SESSION      # Attach to the session"
echo "  Ctrl-b n / Ctrl-b p          # Switch between windows"
echo "  Ctrl-b 0-4                   # Jump to specific window"
echo ""
echo "  Each window runs Claude Code interactively — watch live progress."
echo ""
echo "  When all tasks complete, check PRs:"
echo "    gh pr list --repo ketani23/steward"
echo ""
