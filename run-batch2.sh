#!/bin/zsh
# run-batch2.sh — Launch parallel Claude Code instances for Batch 2
#
# Usage: ./run-batch2.sh
#
# Creates git worktrees and runs Claude Code in non-interactive mode
# with output logged to files. Use `tail -f /tmp/steward-*.log` to monitor.

set -euo pipefail

REPO_DIR="$HOME/Projects/steward"
LOG_DIR="/tmp"
SESSION="steward-batch2"

# Batch 2 tasks
BRANCHES=("mcp-manifest" "egress-filter" "mcp-schema-rewrite" "circuit-breaker")
TASK_FILES=("TASK-2.1.md" "TASK-2.2.md" "TASK-2.3.md" "TASK-2.4.md")

# Ensure we're on latest main
cd "$REPO_DIR"
echo "Ensuring main is up to date..."
git checkout main
git pull origin main 2>/dev/null || true

# Create tmux session for monitoring
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -n "monitor"

for i in {1..${#BRANCHES[@]}}; do
  branch="${BRANCHES[$i]}"
  task_file="${TASK_FILES[$i]}"
  wt_dir="${REPO_DIR}-wt-${branch}"
  feat_branch="feat/${branch}"
  log_file="${LOG_DIR}/steward-${branch}.log"

  echo ""
  echo "=== Setting up ${feat_branch} ==="

  # Create worktree (remove stale one if exists)
  if [ -d "$wt_dir" ]; then
    echo "  Removing existing worktree at $wt_dir"
    git worktree remove "$wt_dir" --force 2>/dev/null || rm -rf "$wt_dir"
  fi

  # Delete branch if it exists locally
  git branch -D "$feat_branch" 2>/dev/null || true

  echo "  Creating worktree: $wt_dir on $feat_branch"
  git worktree add "$wt_dir" -b "$feat_branch"

  # Clear old log
  > "$log_file"

  # Create tmux window and run claude in non-interactive mode
  echo "  Creating tmux window: $branch"
  tmux new-window -t "$SESSION" -n "$branch"

  # Run claude -p (non-interactive) with output visible in tmux AND logged to file
  PROMPT="Read the file docs/tasks/${task_file} and implement everything described in it. Follow all instructions in CLAUDE.md. When done, push your branch and create a PR."
  tmux send-keys -t "$SESSION:$branch" "cd $wt_dir && claude -p '$PROMPT' --permission-mode dontAsk 2>&1 | tee $log_file; echo '=== CLAUDE EXITED ===' >> $log_file" Enter

  echo "  Launched Claude Code for $task_file → $log_file"
done

# Set up monitor window with tail -f on all logs
tmux send-keys -t "$SESSION:monitor" "tail -f /tmp/steward-mcp-manifest.log /tmp/steward-egress-filter.log /tmp/steward-mcp-schema-rewrite.log /tmp/steward-circuit-breaker.log" Enter

echo ""
echo "================================================"
echo "  All 4 tasks launched in tmux session: $SESSION"
echo "================================================"
echo ""
echo "  tmux attach -t $SESSION           # Attach to session"
echo "  Ctrl-b n / Ctrl-b p               # Switch windows"
echo "  Window 'monitor' tails all logs"
echo ""
echo "  Log files:"
echo "    /tmp/steward-mcp-manifest.log"
echo "    /tmp/steward-egress-filter.log"
echo "    /tmp/steward-mcp-schema-rewrite.log"
echo "    /tmp/steward-circuit-breaker.log"
echo ""
echo "  Check progress from another session:"
echo "    tail -f /tmp/steward-*.log"
echo "    grep 'CLAUDE EXITED' /tmp/steward-*.log  # Check which are done"
echo ""
echo "  When all tasks complete, check PRs:"
echo "    gh pr list --repo ketani23/steward"
echo ""
