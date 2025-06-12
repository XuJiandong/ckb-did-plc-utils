import * as cbor from "@ipld/dag-cbor";
import {
  hexFrom,
  Transaction,
  Hex,
  hashTypeId,
  bytesFrom,
  Bytes,
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

function newStagingId(binaryDid: Hex): Bytes {
  let did = bytesFrom(binaryDid);
  let str = "web5:plc:" + uint8arrays.toString(did, "base32");
  return uint8arrays.fromString(str, "utf8");
}

async function main(
  result: plc.PlcResult,
  config: {
    inputCellCount?: number;
    outputCellCount?: number;
    noAssociatePlc?: boolean;
  },
  isFailed?: boolean,
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
  let typeScript = script.clone();
  let transferredFrom = null;

  const inputCell = resource.mockCell(alwaysSuccessScript);
  tx.inputs.push(Resource.createCellInput(inputCell));

  let typeId = hashTypeId(tx.inputs[0], 0);
  // 20 bytes Type ID.
  typeScript.args = hexFrom(typeId.slice(0, 42));

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
  tx.outputs.push(Resource.createCellOutput(alwaysSuccessScript, typeScript));
  tx.outputsData.push(hexFrom(didWeb5Data.toBytes()));

  let txHash = tx.hash();
  await plc.signDidWeb5(result, 0, txHash);

  if (!config?.noAssociatePlc) {
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
  if (isFailed) {
    await verifier.verifyFailure(undefined, false);
    return 0;
  } else {
    return verifier.verifySuccess(true);
  }
}

describe("did-web5-ts", () => {
  beforeAll(async () => {});
  test("it should process a genesis operation without associated did:plc correctly", async () => {
    let result = await plc.generateOperation();
    await main(result, { noAssociatePlc: true });
  });
  test("it should process a genesis operation with associated did:plc correctly", async () => {
    let result = await plc.generateOperation();
    await main(result, { noAssociatePlc: false });
  });
});
