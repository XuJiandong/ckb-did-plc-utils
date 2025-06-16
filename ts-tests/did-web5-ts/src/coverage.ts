import { ScriptVerificationResult } from "ckb-testtool";
import {
  spawnSync,
  SpawnSyncOptionsWithBufferEncoding,
} from "node:child_process";

let globalIndex: number = 0;

export function runCoverage(
  groupType: "lock" | "type",
  cellType: "input" | "output",
  index: number,
  txFile: string,
  shouldFail: boolean,
): ScriptVerificationResult {
  let output = `coverage-data/${globalIndex}.lcov`;
  globalIndex += 1;
  const config: SpawnSyncOptionsWithBufferEncoding = {
    input: txFile,
  };
  const fullArgs = `--tx-file - --cell-type ${cellType} --script-group-type ${groupType} --cell-index ${index} --enable-coverage --coverage-output=${output}`;
  const args = fullArgs.split(" ");
  const result = spawnSync("ckb-debugger", args, config);
  if (shouldFail) {
    if (result.status === 0) {
      console.log(`${result.stdout}`);
      console.log(`${result.stderr}`);
    }
    expect(result.status).toBeGreaterThan(0);
  } else {
    if (result.status !== 0) {
      console.log(`${result.stdout}`);
      console.log(`${result.stderr}`);
    }
    expect(result.status).toBe(0);
  }
  return new ScriptVerificationResult(
    groupType,
    cellType,
    index,
    result.status,
    result.stdout.toString(),
    result.stderr.toString(),
  );
}
