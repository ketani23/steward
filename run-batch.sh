#!/bin/zsh
# run-batch.sh — Launch parallel Claude Code instances for a batch
#
# Usage: ./run-batch.sh <batch-number>
#   e.g. ./run-batch.sh 3
#
# Creates git worktrees, runs Claude Code in non-interactive mode,
# logs output, prevents sleep, and exits cleanly when all tasks complete.
#
# Configure batches below by adding a new section to the case statement.

set -euo pipefail

BATCH="${1:?Usage: ./run-batch.sh <batch-number>}"
REPO_DIR="$HOME/Projects/steward"
LOG_DIR="/tmp"
SESSION="steward-batch${BATCH}"

# --- Batch definitions ---
case "$BATCH" in
  1)
    BRANCHES=("leak-detector" "ingress-sanitizer" "audit-logger" "permission-engine")
    TASK_FILES=("TASK-1.1.md" "TASK-1.2.md" "TASK-1.3.md" "TASK-1.4.md")
    ;;
  2)
    BRANCHES=("mcp-manifest" "egress-filter" "mcp-schema-rewrite" "circuit-breaker")
    TASK_FILES=("TASK-2.1.md" "TASK-2.2.md" "TASK-2.3.md" "TASK-2.4.md")
    ;;
  3)
    BRANCHES=("memory-store" "memory-search" "mcp-transport-stdio" "mcp-transport-http")
    TASK_FILES=("TASK-3.1.md" "TASK-3.2.md" "TASK-3.3.md" "TASK-3.4.md")
    ;;
  4)
    BRANCHES=("secret-broker" "llm-provider" "guardian" "config-management")
    TASK_FILES=("TASK-4.1.md" "TASK-4.2.md" "TASK-4.3.md" "TASK-4.4.md")
    ;;
  5)
    BRANCHES=("mcp-proxy-core" "agent-core" "tool-registry")
    TASK_FILES=("TASK-5.1.md" "TASK-5.2.md" "TASK-5.3.md")
    ;;
  6)
    BRANCHES=("whatsapp-channel" "e2e-smoke")
    TASK_FILES=("TASK-6.1.md" "TASK-6.2.md")
    ;;
  *)
    echo "Unknown batch: $BATCH"
    exit 1
    ;;
esac

# Ensure we're on latest main
cd "$REPO_DIR"
echo "Ensuring main is up to date..."
git checkout main
git pull origin main 2>/dev/null || true

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Launch each task in its own tmux session
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
  git branch -D "$feat_branch" 2>/dev/null || true

  echo "  Creating worktree: $wt_dir on $feat_branch"
  git worktree add "$wt_dir" -b "$feat_branch"

  # Clear old log
  > "$log_file"

  # Launch claude in its own tmux session
  PROMPT="Read the file docs/tasks/${task_file} and implement everything described in it. Follow all instructions in CLAUDE.md. When done, push your branch and create a PR."
  TMUX_SESSION="${SESSION}-${branch}"

  echo "  Launching tmux session: $TMUX_SESSION"
  tmux new-session -d -s "$TMUX_SESSION" -c "$wt_dir" \
    "claude -p '${PROMPT}' --permission-mode dontAsk 2>&1 | tee ${log_file}; echo '=== CLAUDE EXITED ===' >> ${log_file}; echo 'Done. Closing in 30s...'; sleep 30"

  echo "  Launched Claude Code for $task_file → $log_file"
done

echo ""
echo "================================================"
echo "  All ${#BRANCHES[@]} tasks launched for batch $BATCH"
echo "================================================"

# --- Monitor: wait for all sessions to finish ---
monitor_all() {
  while true; do
    alive=0
    for i in {1..${#BRANCHES[@]}}; do
      branch="${BRANCHES[$i]}"
      tmux has-session -t "${SESSION}-${branch}" 2>/dev/null && alive=$((alive + 1))
    done
    if [ "$alive" -eq 0 ]; then
      echo ""
      echo "All batch $BATCH sessions complete."
      exit 0
    fi
    echo "  [$(date +%H:%M)] $alive task(s) still running..."
    sleep 60
  done
}

echo ""
echo "  Monitor: tail -f /tmp/steward-*.log"
echo "  Check done: grep 'CLAUDE EXITED' /tmp/steward-*.log"
echo "  List sessions: tmux list-sessions | grep steward"
echo ""
echo "  Preventing sleep until all tasks finish..."
echo ""

monitor_all &
MONITOR_PID=$!

# caffeinate watches the monitor — machine can sleep when it exits
caffeinate -i -s -w "$MONITOR_PID"

echo "All done. Machine can sleep now."
