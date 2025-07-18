import * as cbor from "@ipld/dag-cbor";
import {
  hexFrom,
  Transaction,
  Hex,
  hashTypeId,
  bytesFrom,
  WitnessArgs,
  numFrom,
  OutPoint,
  CellOutput,
  Cell,
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
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto";

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

function newLocalId(binaryDid: Hex): Hex {
  let did = bytesFrom(binaryDid);
  let str = "did:plc:" + uint8arrays.toString(did, "base32");
  return hexFrom(uint8arrays.fromString(str, "utf8"));
}

function jsonify(obj: any): any {
  return JSON.parse(
    JSON.stringify(
      obj,
      (_, value) =>
        typeof value === "bigint" ? `0x${value.toString(16)}` : value,
      2,
    ),
  );
}

async function main(
  result: plc.PlcOperationResult,
  config: {
    inputCellCount?: number;
    outputCellCount?: number;
    noAssociatePlc?: boolean;
    update?: boolean;
    updateLocalId?: boolean;
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
    transferredFrom = newLocalId(result.binaryDid);
  }
  // When testing invalid CBOR scenarios, use "0x82" which represents a CBOR array
  // expecting 2 elements but provides none, making it invalid CBOR format
  let cborData = config?.invalidCbor ? bytesFrom("0x82") : cbor.encode("");
  let didWeb5Data = molecule.DidWeb5Data.from({
    value: {
      document: cborData,
      localId: transferredFrom,
    },
  });

  if (config?.update || config?.updateLocalId) {
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
      if (config?.updateLocalId) {
        newDidWeb5Data.value.localId = hexFrom(newLocalId("0x00"));
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
      result.rotationKeyIndices.push(0n);
      result.sig = "0x00";
    } else {
      await plc.signDidWeb5(result, 0, txHash);
    }
    if (!result.sig) {
      throw new Error("Signature is required");
    }
    let web5Witness = molecule.DidWeb5Witness.from({
      localIdAuthorization: {
        history: result.history,
        sig: result.sig,
        rotationKeyIndices: result.rotationKeyIndices,
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
  test("it should reject an update with local id changed", async () => {
    let result = await plc.generateOperations();
    await main(result, { updateLocalId: true }, true);
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

  test("it should re-create the spec example", async () => {
    let previousTxHash: Hex =
      "0x1ecbf88d692a14d7cbc0bfd1a3d5019e4b613247ae438bad52f94148c6009559";
    const did = "0x8434cfe81aa825c275d513eee20e4235294e3420";

    const resource = Resource.default();
    resource.cellOutpointHash = previousTxHash;
    const baseTx = Transaction.default();
    const typeScript = resource.deployCell(DEFAULT_SCRIPT_HEX, baseTx, true);
    typeScript.args = did;
    const alwaysSuccessScript = resource.deployCell(
      ALWAYS_SUCCESS_HEX,
      baseTx,
      true,
    );

    const doc0 = {
      verificationMethods: {
        atproto: "did:key:zSigningKey",
      },
      alsoKnownAs: ["at://alice.test"],
      services: {
        atproto_pds: {
          type: "AtprotoPersonalDataServer",
          endpoint: "https://example.test",
        },
      },
    };
    const doc1 = {
      verificationMethods: {
        atproto: "did:key:zSigningKey",
      },
      alsoKnownAs: ["at://bob.test"],
      services: {
        atproto_pds: {
          type: "AtprotoPersonalDataServer",
          endpoint: "https://example.test",
        },
      },
    };

    const didWeb5Data0 = molecule.DidWeb5Data.from({
      value: {
        document: cbor.encode(doc0),
        localId: null,
      },
    });
    const didWeb5Data1 = molecule.DidWeb5Data.from({
      value: {
        document: cbor.encode(doc1),
        localId: null,
      },
    });

    expect(didWeb5Data0).toMatchSnapshot("data0");
    expect(didWeb5Data1).toMatchSnapshot("data1");

    // Creation Example
    {
      const tx = Transaction.default();
      tx.cellDeps = baseTx.cellDeps;
      const inputCell = resource.mockCell(alwaysSuccessScript);
      tx.inputs.push(Resource.createCellInput(inputCell));

      const typeId = hashTypeId(tx.inputs[0], 0);
      typeScript.args = hexFrom(typeId.slice(0, 42)); // 20 bytes Type ID
      expect(hexFrom(typeId.slice(0, 42))).toBe(did);

      tx.outputs.push(
        Resource.createCellOutput(
          alwaysSuccessScript,
          typeScript,
          numFrom(600),
        ),
      );
      tx.outputsData.push(hexFrom(didWeb5Data0.toBytes()));

      const verifier = Verifier.from(resource, tx);
      const txJson = jsonify(tx);

      expect(tx.hash()).toMatchSnapshot("creation-tx-hash");
      expect(txJson).toMatchSnapshot("creation-tx");
      verifier.verifySuccess(true, { codeHash: typeScript.hash() });

      previousTxHash = tx.hash();
    }

    // Update Example
    {
      const tx = Transaction.default();
      tx.cellDeps = baseTx.cellDeps;

      const inputCell = new Cell(
        new OutPoint(previousTxHash, numFrom(0)),
        new CellOutput(numFrom(600), alwaysSuccessScript, typeScript),
        hexFrom(didWeb5Data0.toBytes()),
      );
      resource.cells.set(inputCell.outPoint.toBytes().toString(), inputCell);
      tx.inputs.push(Resource.createCellInput(inputCell));

      tx.outputs.push(
        Resource.createCellOutput(
          alwaysSuccessScript,
          typeScript,
          numFrom(599),
        ),
      );
      tx.outputsData.push(hexFrom(didWeb5Data1.toBytes()));

      const verifier = Verifier.from(resource, tx);
      const txJson = jsonify(tx);

      expect(tx.hash()).toMatchSnapshot("update-tx-hash");
      expect(txJson).toMatchSnapshot("update-tx");
      verifier.verifySuccess(true, { codeHash: typeScript.hash() });

      previousTxHash = tx.hash();
    }

    // Deactivation Example
    {
      const tx = Transaction.default();
      tx.cellDeps = baseTx.cellDeps;

      const inputCell = new Cell(
        new OutPoint(previousTxHash, numFrom(0)),
        new CellOutput(numFrom(599), alwaysSuccessScript, typeScript),
        hexFrom(didWeb5Data1.toBytes()),
      );
      resource.cells.set(inputCell.outPoint.toBytes().toString(), inputCell);
      tx.inputs.push(Resource.createCellInput(inputCell));

      tx.outputs.push(
        Resource.createCellOutput(alwaysSuccessScript, undefined, numFrom(598)),
      );
      tx.outputsData.push("0x");

      const verifier = Verifier.from(resource, tx);
      const txJson = jsonify(tx);

      expect(txJson).toMatchSnapshot("deactivation-tx");
      verifier.verifySuccess(true, { codeHash: typeScript.hash() });

      previousTxHash = tx.hash();
    }
  });

  test("it should re-create the local id extension example", async () => {
    const previousTxHash: Hex =
      "0x1ecbf88d692a14d7cbc0bfd1a3d5019e4b613247ae438bad52f94148c6009559";
    const did = "0x8434cfe81aa825c275d513eee20e4235294e3420";

    const key = await Secp256k1Keypair.import(
      "32288e73ba3cc99b0d2499f20c08cf4ef90d4f4f914ce21221d81a386bbc7e44",
    );
    const rotationKey1 = await Secp256k1Keypair.import(
      "1f8b611642074eac6733331e2120de2a83e983775391706649abefc2995bae73",
    );
    let rotationKey2 = await P256Keypair.import(
      "e7d9916064bcf1c5e80ef5882f84171dc0a46fb7c40f5b29a671f9155e172482",
    );

    const migration = await plc.generateOperations({
      key,
      rotationKey1,
      rotationKey2,
    });
    const localId = newLocalId(migration.binaryDid);
    expect(uint8arrays.toString(bytesFrom(localId))).toMatchSnapshot(
      "local-id",
    );

    const resource = Resource.default();
    resource.cellOutpointHash = previousTxHash;
    const tx = Transaction.default();
    const typeScript = resource.deployCell(DEFAULT_SCRIPT_HEX, tx, true);
    typeScript.args = did;
    const alwaysSuccessScript = resource.deployCell(
      ALWAYS_SUCCESS_HEX,
      tx,
      true,
    );

    const doc = {
      verificationMethods: {
        atproto: "did:key:zSigningKey",
      },
      alsoKnownAs: ["at://alice.test"],
      services: {
        atproto_pds: {
          type: "AtprotoPersonalDataServer",
          endpoint: "https://example.test",
        },
      },
    };
    const didWeb5Data = molecule.DidWeb5Data.from({
      value: {
        document: cbor.encode(doc),
        localId,
      },
    });

    // Migration Example
    const inputCell = resource.mockCell(alwaysSuccessScript);
    tx.inputs.push(Resource.createCellInput(inputCell));

    const typeId = hashTypeId(tx.inputs[0], 0);
    typeScript.args = hexFrom(typeId.slice(0, 42)); // 20 bytes Type ID
    expect(hexFrom(typeId.slice(0, 42))).toBe(did);

    tx.outputs.push(
      Resource.createCellOutput(alwaysSuccessScript, typeScript, numFrom(600)),
    );
    tx.outputsData.push(hexFrom(didWeb5Data.toBytes()));

    await plc.signDidWeb5(migration, 0, tx.hash());
    expect(migration.sig).toBeTruthy();
    if (!migration.sig) {
      throw new Error("Signature is required");
    }
    expect(cbor.decode(bytesFrom(migration.history[0]!))).toMatchSnapshot(
      "plc-genesis-op",
    );
    const web5Witness = molecule.DidWeb5Witness.from({
      localIdAuthorization: {
        history: migration.history,
        sig: migration.sig,
        rotationKeyIndices: migration.rotationKeyIndices,
      },
    });
    expect(jsonify(web5Witness)).toMatchSnapshot("witness");
    let witnessArgs = WitnessArgs.from({
      outputType: web5Witness.toBytes(),
    });
    tx.setWitnessArgsAt(0, witnessArgs);
    const verifier = Verifier.from(resource, tx);
    const txJson = jsonify(tx);

    expect(tx.hash()).toMatchSnapshot("local-id-migration-tx-hash");
    expect(txJson).toMatchSnapshot("local-id-migration-tx");
    verifier.verifySuccess(true, { codeHash: typeScript.hash() });
  });
});
