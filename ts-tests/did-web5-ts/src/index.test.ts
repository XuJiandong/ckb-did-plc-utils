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

export const DEFAULT_SCRIPT = path.join(
  __dirname,
  "../../../build/release/did-web5-ts",
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
  },
  shouldFail?: boolean,
): Promise<number> {
  const resource = Resource.default();
  const tx = Transaction.default();

  const script = resource.deployCell(
    hexFrom(readFileSync(DEFAULT_SCRIPT)),
    tx,
    false,
  );
  const alwaysSuccessScript = resource.deployCell(
    hexFrom(readFileSync(DEFAULT_SCRIPT_ALWAYS_SUCCESS)),
    tx,
    false,
  );
  let transferredFrom: Hex | null = null;

  // cell data
  if (config?.noAssociatePlc) {
    transferredFrom = null;
  } else {
    transferredFrom = newStagingId(result.binaryDid);
  }
  let didWeb5Data = molecule.DidWeb5Data.from({
    value: {
      document: cbor.encode(""),
      transferredFrom,
    },
  });

  if (config?.update || config?.updateStagingId) {
    // script args
    let typeScript = script.clone();
    typeScript.args = hexFrom("0x" + "0".repeat(40));
    const inputCell = resource.mockCell(
      alwaysSuccessScript,
      typeScript,
      hexFrom(didWeb5Data.toBytes()),
    );
    // input cells
    tx.inputs.push(Resource.createCellInput(inputCell));

    // output cells
    tx.outputs.push(Resource.createCellOutput(alwaysSuccessScript, typeScript));
    let newDidWeb5Data = didWeb5Data.clone();
    if (config?.updateStagingId) {
      newDidWeb5Data.value.transferredFrom = hexFrom(newStagingId("0x00"));
    } else {
      newDidWeb5Data.value.document = hexFrom(
        cbor.encode({ key: "hello, world" }),
      );
    }
    tx.outputsData.push(hexFrom(newDidWeb5Data.toBytes()));
  } else {
    // input cells
    const inputCell = resource.mockCell(alwaysSuccessScript);
    tx.inputs.push(Resource.createCellInput(inputCell));

    // Note: Type script args must be computed after input cells are added to the transaction
    // because the type ID depends on the first input cell's outpoint
    let typeScript = script.clone();
    let typeId = hashTypeId(tx.inputs[0], 0);
    typeScript.args = hexFrom(typeId.slice(0, 42)); // 20 bytes Type ID

    // output cells
    tx.outputs.push(Resource.createCellOutput(alwaysSuccessScript, typeScript));
    tx.outputsData.push(hexFrom(didWeb5Data.toBytes()));
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
  if (shouldFail) {
    await verifier.verifyFailure(undefined, false);
    return 0;
  } else {
    return verifier.verifySuccess(true);
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
  test("it should process several operations with associated did:plc correctly", async () => {
    let result = await plc.generateOperations({ moreOps: true });
    await main(result, {});
  });
  test("it should process an update correctly", async () => {
    let result = await plc.generateOperations();
    await main(result, { update: true });
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
});
