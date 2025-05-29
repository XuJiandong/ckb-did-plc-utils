import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto";
import {
  atprotoOp,
  didForCreateOp,
  Operation,
  updateHandleOp,
  updateRotationKeysOp,
  getLastOpWithCid,
  tombstoneOp,
} from "@did-plc/lib";
import * as cbor from "@ipld/dag-cbor";

import { hexFrom, Transaction, Hex } from "@ckb-ccc/core";
import { readFileSync } from "fs";
import { Resource, Verifier } from "ckb-testtool";
import path from "path";
import * as uint8arrays from "uint8arrays";

export const DEFAULT_SCRIPT = path.join(
  __dirname,
  "../../../build/release/ckb-did-plc-registry",
);

function getBinaryDid(did: string) {
  if (!did.startsWith("did:plc:")) {
    throw new Error("Invalid DID");
  }
  let did_without_prefix = did.slice(8);
  const decoded = uint8arrays.fromString(did_without_prefix, "base32");
  return hexFrom(decoded);
}

async function main(
  did: Hex,
  curData: Hex,
  prevData?: Hex,
  isFailed?: boolean,
  config?: {
    inputCellCount?: number;
    outputCellCount?: number;
  },
): Promise<number> {
  const resource = Resource.default();
  const tx = Transaction.default();

  const script = resource.deployCell(
    hexFrom(readFileSync(DEFAULT_SCRIPT)),
    tx,
    false,
  );
  let lockScript = script.clone();
  let typeScript = script.clone();
  typeScript.args = hexFrom("0x01" + did.slice(2));

  let inputCellCount = config?.inputCellCount ?? 1;
  let outputCellCount = config?.outputCellCount ?? 1;

  if (prevData != null) {
    for (let i = 0; i < inputCellCount; i++) {
      const inputCell = resource.mockCell(lockScript, typeScript, prevData);
      tx.inputs.push(Resource.createCellInput(inputCell));
    }
  }

  for (let i = 0; i < outputCellCount; i++) {
    tx.outputs.push(Resource.createCellOutput(lockScript, typeScript));
    tx.outputsData.push(curData);
  }

  const verifier = Verifier.from(resource, tx);
  if (isFailed) {
    await verifier.verifyFailure(undefined, true);
    return 0;
  } else {
    return verifier.verifySuccess(true);
  }
}

describe("CKB DID PLC Registry", () => {
  const ops: Operation[] = [];
  let signingKey: Secp256k1Keypair;
  let rotationKey1: Secp256k1Keypair;
  let rotationKey2: P256Keypair;
  let wrongKey: Secp256k1Keypair;
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let binaryDid: Hex = "0x";
  let noPrefix = "at://alice.example3.com";

  beforeAll(async () => {
    signingKey = await Secp256k1Keypair.create();
    rotationKey1 = await Secp256k1Keypair.create();
    rotationKey2 = await P256Keypair.create();
    wrongKey = await Secp256k1Keypair.create();
  });

  const lastOp = () => {
    const lastOp = ops.at(-1);
    if (!lastOp) {
      throw new Error("expected an op on log");
    }
    return lastOp;
  };

  test("it should process a genesis operation correctly", async () => {
    const createOp = await atprotoOp({
      signingKey: signingKey.did(),
      rotationKeys: [rotationKey1.did(), rotationKey2.did()],
      handle,
      pds: atpPds,
      prev: null,
      signer: rotationKey1,
    });
    ops.push(createOp);
    let did = await didForCreateOp(createOp);
    binaryDid = getBinaryDid(did);
    let operation = cbor.encode(createOp);
    main(binaryDid, hexFrom(operation));
  });

  test("it should update content with secp256k1 signature", async () => {
    handle = "at://ali.example2.com";
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), rotationKey1, handle);
    ops.push(op);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData));
  });

  test("it should update content with secp256r1 signature", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), rotationKey2, noPrefix);
    ops.push(op);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData));
  });

  test("it should reject updates with wrong rotation key", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), wrongKey, noPrefix);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData), true);
  });

  test("it should reject updates with more than 2 output cells", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), wrongKey, noPrefix);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData), true, {
      outputCellCount: 2,
    });
  });
  test("it should reject updates with more than 2 input cells", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), wrongKey, noPrefix);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData), true, {
      inputCellCount: 2,
    });
  });
  test("it should reject updates with zero output cells", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), wrongKey, noPrefix);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData), true, {
      outputCellCount: 0,
    });
  });

  test("it should reject updates with invalid signature", async () => {
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), rotationKey1, noPrefix);
    let binarySig = uint8arrays.fromString(op.sig, "base64url");
    binarySig[0] ^= 1;
    op.sig = uint8arrays.toString(binarySig, "base64url");
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData), true);
  });

  test("it should successfully rotate rotation keys", async () => {
    const newRotationKey = await Secp256k1Keypair.create();
    const op = await updateRotationKeysOp(lastOp(), rotationKey1, [
      newRotationKey.did(),
      rotationKey2.did(),
    ]);
    let prevData = cbor.encode(lastOp());
    ops.push(op);
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData));
  });

  // this test should be at last. No operation is allowed after that.
  test("it should allow tombstoning a DID", async () => {
    const last = await getLastOpWithCid(ops);
    const op = await tombstoneOp(last.cid, rotationKey2);
    let prevData = cbor.encode(lastOp());
    let curData = cbor.encode(op);
    main(binaryDid, hexFrom(curData), hexFrom(prevData));
  });
});

describe("CKB DID PLC Registry benchmark", () => {
  // this test case is for the maximum rotation keys with worst performance.
  test("it should process genesis operation with maximum rotation keys within cycle limits", async () => {
    let rotationKey1 = await P256Keypair.create();
    let rotationKey2 = await P256Keypair.create();
    let rotationKey3 = await P256Keypair.create();
    let rotationKey4 = await P256Keypair.create();
    let rotationKey5 = await P256Keypair.create();
    let signingKey = await Secp256k1Keypair.create();

    const createOp = await atprotoOp({
      signingKey: signingKey.did(),
      rotationKeys: [
        rotationKey1.did(),
        rotationKey2.did(),
        rotationKey3.did(),
        rotationKey4.did(),
        rotationKey5.did(),
      ],
      handle: "at://alice.example.com",
      pds: "https://example.com",
      prev: null,
      signer: rotationKey5,
    });
    let did = await didForCreateOp(createOp);
    let binary_did = getBinaryDid(did);
    let operation = cbor.encode(createOp);
    let cycles = await main(binary_did, hexFrom(operation));
    expect(cycles).toBeLessThan(26000000);
  });
});
