import { ScriptVerificationResult } from "ckb-testtool";
import {
  spawnSync,
  SpawnSyncOptionsWithBufferEncoding,
} from "node:child_process";

export function runCoverage(
  groupType: "lock" | "type",
  cellType: "input" | "output",
  index: number,
  txFile: string,
  output: string,
): ScriptVerificationResult {
  const config: SpawnSyncOptionsWithBufferEncoding = {
    input: txFile,
  };
  const fullArgs = `--enable-coverage --coverage-output=${output} --tx-file - --cell-type ${cellType} --script-group-type ${groupType} --cell-index ${index}`;
  const args = fullArgs.split(" ");
  const result = spawnSync("ckb-debugger", args, config);
  return new ScriptVerificationResult(
    groupType,
    cellType,
    index,
    result.status,
    result.stdout.toString(),
    result.stderr.toString(),
  );
}
