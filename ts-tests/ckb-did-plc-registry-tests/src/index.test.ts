import { check } from "@atproto/common";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto";
import {
  atprotoOp,
  didForCreateOp,
  Operation,
  def,
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
import { fromString } from "uint8arrays";

export const DEFAULT_SCRIPT = path.join(
  __dirname,
  "../../../build/release/ckb-did-plc-registry",
);

function getBinaryDid(did: string) {
  if (!did.startsWith("did:plc:")) {
    throw new Error("Invalid DID");
  }
  let did_without_prefix = did.slice(8);
  const decoded = fromString(did_without_prefix, "base32");
  return hexFrom(decoded);
}

async function main(did: Hex, curData: Hex, prevData?: Hex): Promise<number> {
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

  if (prevData != null) {
    const inputCell = resource.mockCell(lockScript, typeScript, prevData);
    tx.inputs.push(Resource.createCellInput(inputCell));
  }

  tx.outputs.push(Resource.createCellOutput(lockScript, typeScript));
  tx.outputsData.push(curData);

  const verifier = Verifier.from(resource, tx);
  return verifier.verifySuccess(false);
}

describe("CKB DID PLC Registry", () => {
  const ops: Operation[] = [];
  let signingKey: Secp256k1Keypair;
  let rotationKey1: Secp256k1Keypair;
  let rotationKey2: P256Keypair;
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let binary_did: Hex = "0x";

  beforeAll(async () => {
    signingKey = await Secp256k1Keypair.create();
    rotationKey1 = await Secp256k1Keypair.create();
    rotationKey2 = await P256Keypair.create();
  });

  const lastOp = () => {
    const lastOp = ops.at(-1);
    if (!lastOp) {
      throw new Error("expected an op on log");
    }
    return lastOp;
  };

  test("genesis operation", async () => {
    const createOp = await atprotoOp({
      signingKey: signingKey.did(),
      rotationKeys: [rotationKey1.did(), rotationKey2.did()],
      handle,
      pds: atpPds,
      prev: null,
      signer: rotationKey1,
    });
    const isValid = check.is(createOp, def.operation);
    expect(isValid).toBeTruthy();
    ops.push(createOp);
    let did = await didForCreateOp(createOp);
    binary_did = getBinaryDid(did);
    let operation = cbor.encode(createOp);
    main(binary_did, hexFrom(operation));
  });

  test("update content with secp256k1", async () => {
    const noPrefix = "ali.example2.com";
    handle = `at://${noPrefix}`;
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), rotationKey1, noPrefix);
    ops.push(op);
    let curData = cbor.encode(op);
    main(binary_did, hexFrom(curData), hexFrom(prevData));
  });
  test("update content with secp256r1", async () => {
    const noPrefix = "ali.example3.com";
    handle = `at://${noPrefix}`;
    let prevData = cbor.encode(lastOp());
    const op = await updateHandleOp(lastOp(), rotationKey2, noPrefix);
    ops.push(op);
    let curData = cbor.encode(op);
    main(binary_did, hexFrom(curData), hexFrom(prevData));
  });
  test("rotates rotation keys", async () => {
    const newRotationKey = await Secp256k1Keypair.create();
    const op = await updateRotationKeysOp(lastOp(), rotationKey1, [
      newRotationKey.did(),
      rotationKey2.did(),
    ]);
    let prevData = cbor.encode(lastOp());
    ops.push(op);
    let curData = cbor.encode(op);
    main(binary_did, hexFrom(curData), hexFrom(prevData));
  });

  // this test should be at last. No operation is allowed after that.
  test("allows tombstoning a DID", async () => {
    const last = await getLastOpWithCid(ops);
    const op = await tombstoneOp(last.cid, rotationKey2);
    let prevData = cbor.encode(lastOp());
    let curData = cbor.encode(op);
    main(binary_did, hexFrom(curData), hexFrom(prevData));
  });

  // this test case is for the maximum rotation keys with worst performance.
  test("genesis operation with maximum rotation keys", async () => {
    let rotationKey1 = await P256Keypair.create();
    let rotationKey2 = await P256Keypair.create();
    let rotationKey3 = await P256Keypair.create();
    let rotationKey4 = await P256Keypair.create();
    let rotationKey5 = await P256Keypair.create();

    const createOp = await atprotoOp({
      signingKey: signingKey.did(),
      rotationKeys: [
        rotationKey1.did(),
        rotationKey2.did(),
        rotationKey3.did(),
        rotationKey4.did(),
        rotationKey5.did(),
      ],
      handle,
      pds: atpPds,
      prev: null,
      signer: rotationKey5,
    });
    const isValid = check.is(createOp, def.operation);
    expect(isValid).toBeTruthy();
    let did = await didForCreateOp(createOp);
    binary_did = getBinaryDid(did);
    let operation = cbor.encode(createOp);
    let cycles = await main(binary_did, hexFrom(operation));
    expect(cycles).toBeLessThan(26000000);
  });
});
