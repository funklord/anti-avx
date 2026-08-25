#!/bin/sh
# Run ddisasm under hard resource bounds, and report what it actually cost.
#
# ddisasm runs a Souffle Datalog analysis whose working set grows with the
# instruction count. On a 102 MB binary that is 16.5 million instructions,
# and nobody has published what that costs. An unbounded run that does not
# fit takes the machine into swap rather than failing, which is the failure
# mode this wrapper exists to prevent -- see ~/.claude/guidelines/
# running-code.md, where 693 GB and 15 GB of RSS were both lost that way.
#
# Three bounds, none of which the tool can talk its way out of:
#
#   prlimit --as    a hard ceiling on address space; malloc fails and the
#                   process dies instead of the machine swapping
#   prlimit --fsize a ceiling on any single file it writes
#   timeout         a wall-clock ceiling
#
# The address-space limit is the important one and it is deliberately below
# total RAM, so that a run which does not fit is reported as a failure of
# the run rather than absorbed by the machine.
#
# usage: run_ddisasm.sh <input> <output.gtirb> [limit_gb] [timeout_s]

set -eu

input=${1:?usage: run_ddisasm.sh <input> <output.gtirb> [limit_gb] [timeout_s]}
output=${2:?usage: run_ddisasm.sh <input> <output.gtirb> [limit_gb] [timeout_s]}
limit_gb=${3:-28}
seconds=${4:-3600}

: "${DDISASM_PREFIX:?set DDISASM_PREFIX to the unpacked ddisasm tree}"

as_kb=$((limit_gb * 1024 * 1024))
fsize_kb=$((32 * 1024 * 1024))		# 32 GB, far above any plausible .gtirb

export LD_LIBRARY_PATH="$DDISASM_PREFIX/usr/lib/x86_64-linux-gnu:$DDISASM_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "run_ddisasm: $input -> $output"
echo "run_ddisasm: address space ${limit_gb} GB, wall clock ${seconds} s, "\
"threads ${DDISASM_THREADS:-4}"

start=$(date +%s)
set +e
prlimit --as=$((as_kb * 1024)) --fsize=$((fsize_kb * 1024)) \
	timeout --signal=KILL "$seconds" \
	/usr/bin/time -v "$DDISASM_PREFIX/usr/bin/ddisasm" \
		"$input" \
		--ir "$output" \
		-j "${DDISASM_THREADS:-4}" \
		>"$output.stdout" 2>"$output.stderr"
status=$?
set -e
finish=$(date +%s)

echo "run_ddisasm: exit $status after $((finish - start))s"
grep -E 'Maximum resident set size|Elapsed \(wall' "$output.stderr" 2>/dev/null || true

if [ "$status" -ne 0 ]; then
	echo "run_ddisasm: FAILED -- last lines of stderr:" >&2
	tail -20 "$output.stderr" >&2
	exit "$status"
fi

ls -l "$output"
