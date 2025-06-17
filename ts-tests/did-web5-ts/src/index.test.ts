import * as cbor from "@ipld/dag-cbor";
import {
  hexFrom,
  Transaction,
  Hex,
  hashTypeId,
  bytesFrom,
  WitnessArgs,
} from "@ckb-ccc/core";
import { readFileSync } from "fs";
import {
  DEFAULT_SCRIPT_ALWAYS_SUCCESS,
  Resource,
  Verifier,
} from "ckb-testtool";
import path from "path";
import { molecule, plc } from "./index";
import * as uint8arrays from "uint8arrays";
import { runCoverage } from "./coverage";

if (process.env.CKB_COVERAGE) {
  console.log(
    "The environment variable CKB_COVERAGE is defined. It's for coverage test only",
  );
}

export const DEFAULT_SCRIPT = path.join(
  __dirname,
  process.env.CKB_COVERAGE
    ? "../../../build/debug/did-web5-ts"
    : "../../../build/release/did-web5-ts",
);

export const DEFAULT_SCRIPT_HEX = hexFrom(readFileSync(DEFAULT_SCRIPT));
export const ALWAYS_SUCCESS_HEX = hexFrom(
  readFileSync(DEFAULT_SCRIPT_ALWAYS_SUCCESS),
);

function newStagingId(binaryDid: Hex): Hex {
  let did = bytesFrom(binaryDid);
  let str = "web5:plc:" + uint8arrays.toString(did, "base32");
  return hexFrom(uint8arrays.fromString(str, "utf8"));
}

async function main(
  result: plc.PlcOperationResult,
  config: {
    inputCellCount?: number;
    outputCellCount?: number;
    noAssociatePlc?: boolean;
    update?: boolean;
    updateStagingId?: boolean;
    invalidSignature?: boolean;
    shortArgs?: boolean;
    invalidCbor?: boolean;
    mismatchedHistory?: boolean;
  },
  shouldFail?: boolean,
): Promise<number> {
  const resource = Resource.default();
  const tx = Transaction.default();
  const script = resource.deployCell(DEFAULT_SCRIPT_HEX, tx, false);
  const alwaysSuccessScript = resource.deployCell(
    ALWAYS_SUCCESS_HEX,
    tx,
    false,
  );
  let transferredFrom: Hex | null = null;
  let codeHashToRun: Hex | null = null;

  // cell data
  if (config?.noAssociatePlc) {
    transferredFrom = null;
  } else {
    transferredFrom = newStagingId(result.binaryDid);
  }
  // When testing invalid CBOR scenarios, use "0x82" which represents a CBOR array
  // expecting 2 elements but provides none, making it invalid CBOR format
  let cborData = config?.invalidCbor ? bytesFrom("0x82") : cbor.encode("");
  let didWeb5Data = molecule.DidWeb5Data.from({
    value: {
      document: cborData,
      transferredFrom,
    },
  });

  if (config?.update || config?.updateStagingId) {
    // script args
    let typeScript = script.clone();
    typeScript.args = hexFrom("0x" + "0".repeat(40));
    codeHashToRun = typeScript.hash();
    const inputCell = resource.mockCell(
      alwaysSuccessScript,
      typeScript,
      hexFrom(didWeb5Data.toBytes()),
    );
    // input cells
    for (let i = 0; i < (config?.inputCellCount ?? 1); i++) {
      tx.inputs.push(Resource.createCellInput(inputCell));
    }

    // output cells
    for (let i = 0; i < (config?.outputCellCount ?? 1); i++) {
      tx.outputs.push(
        Resource.createCellOutput(alwaysSuccessScript, typeScript),
      );
      let newDidWeb5Data = didWeb5Data.clone();
      if (config?.updateStagingId) {
        newDidWeb5Data.value.transferredFrom = hexFrom(newStagingId("0x00"));
      } else {
        newDidWeb5Data.value.document = hexFrom(
          cbor.encode({ key: "hello, world" }),
        );
      }
      tx.outputsData.push(hexFrom(newDidWeb5Data.toBytes()));
    }
  } else {
    // input cells
    const inputCell = resource.mockCell(alwaysSuccessScript);
    tx.inputs.push(Resource.createCellInput(inputCell));

    // Note: Type script args must be computed after input cells are added to the transaction
    // because the type ID depends on the first input cell's outpoint
    let typeScript = script.clone();
    let typeId = hashTypeId(tx.inputs[0], 0);
    typeScript.args = hexFrom(typeId.slice(0, config?.shortArgs ? 10 : 42)); // 20 bytes Type ID
    codeHashToRun = typeScript.hash();

    let count = config?.outputCellCount ?? 1;
    for (let i = 0; i < count; i++) {
      tx.outputs.push(
        Resource.createCellOutput(alwaysSuccessScript, typeScript),
      );
      tx.outputsData.push(hexFrom(didWeb5Data.toBytes()));
    }
  }

  // witness
  if (!config?.noAssociatePlc) {
    let txHash = tx.hash();
    if (config.invalidSignature) {
      result.signingKeys.push(0n);
      result.sig = "0x00";
    } else {
      await plc.signDidWeb5(result, 0, txHash);
    }
    if (!result.sig) {
      throw new Error("Signature is required");
    }
    let web5Witness = molecule.DidWeb5Witness.from({
      transferredFrom: {
        history: result.history,
        sig: result.sig,
        signingKeys: result.signingKeys,
      },
    });
    let witnessArgs = WitnessArgs.from({
      outputType: web5Witness.toBytes(),
    });
    tx.setWitnessArgsAt(0, witnessArgs);
  }

  const verifier = Verifier.from(resource, tx);
  if (process.env.CKB_COVERAGE) {
    const txFile = JSON.stringify(verifier.txFile());
    let count = config?.outputCellCount ?? 1;
    runCoverage(
      "type",
      count === 0 ? "input" : "output",
      0,
      txFile,
      shouldFail ?? false,
    );
    return 0;
  } else {
    if (shouldFail) {
      await verifier.verifyFailure(undefined, false, {
        codeHash: codeHashToRun,
      });
      return 0;
    } else {
      return verifier.verifySuccess(true, { codeHash: codeHashToRun });
    }
  }
}

describe("did-web5-ts", () => {
  test("it should process a genesis operation without associated did:plc correctly", async () => {
    let result = await plc.generateOperations();
    await main(result, { noAssociatePlc: true });
  });
  test("it should process a genesis operation with associated did:plc correctly", async () => {
    let result = await plc.generateOperations();
    await main(result, {});
  });
  test("it should reject invalid cbor format", async () => {
    let result = await plc.generateOperations();
    await main(result, { invalidCbor: true }, true);
  });

  test("it should reject process invalid args (!= 20 bytes)", async () => {
    let result = await plc.generateOperations();
    await main(result, { shortArgs: true }, true);
  });
  test("it should reject multiple output cells while minting", async () => {
    let result = await plc.generateOperations();
    await main(result, { outputCellCount: 2 }, true);
  });
  test("it should process several operations with associated did:plc correctly", async () => {
    let result = await plc.generateOperations({ moreOps: true });
    await main(result, {});
  });
  test("it should process an update correctly", async () => {
    let result = await plc.generateOperations();
    await main(result, { update: true });
  });
  test("it should reject an update with multiple outputs", async () => {
    let result = await plc.generateOperations();
    await main(result, { update: true, outputCellCount: 2 }, true);
  });
  test("it should reject an update with multiple inputs", async () => {
    let result = await plc.generateOperations();
    await main(result, { update: true, inputCellCount: 2 }, true);
  });
  test("it should process an update to burn", async () => {
    let result = await plc.generateOperations();
    await main(result, { update: true, outputCellCount: 0 });
  });
  test("it should reject an update with staging id changed", async () => {
    let result = await plc.generateOperations();
    await main(result, { updateStagingId: true }, true);
  });
  test("it should reject a genesis operation with associated did:plc and invalid signature", async () => {
    let result = await plc.generateOperations();
    await main(result, { invalidSignature: true }, true);
  });
  test("it should reject a genesis operation with associated did:plc and invalid signature 2", async () => {
    let result = await plc.generateOperations({ invalidSignature: true });
    await main(result, {}, true);
  });
  test("it should reject an operation with mismatched history length", async () => {
    let result = await plc.generateOperations({ mismatchedHistory: true });
    await main(result, {}, true);
  });
});
