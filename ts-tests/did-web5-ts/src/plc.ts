import { Keypair, P256Keypair, Secp256k1Keypair } from "@atproto/crypto";
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

import * as uint8arrays from "uint8arrays";
import { bytesFrom, Hex, hexFrom, Num, numFrom } from "@ckb-ccc/core";
import { sign } from "crypto";

function getBinaryDid(did: string): Hex {
  if (!did.startsWith("did:plc:")) {
    throw new Error("Invalid DID");
  }
  let did_without_prefix = did.slice(8);
  const decoded = uint8arrays.fromString(did_without_prefix, "base32");
  return hexFrom(decoded);
}

export type PlcResult = {
  history: Hex[];
  signingKeys: Num[];
  binaryDid: Hex;
  keyPairs: Keypair[];
  sig?: Hex;
};

export async function generateOperation(option?: {}): Promise<PlcResult> {
  const ops: Operation[] = [];
  let key = await Secp256k1Keypair.create();
  let rotationKey1 = await Secp256k1Keypair.create();
  let rotationKey2 = await P256Keypair.create();
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let binaryDid: Hex = "0x";
  let signingKeys: Num[] = [];

  const createOp = await atprotoOp({
    signingKey: key.did(),
    rotationKeys: [rotationKey1.did(), rotationKey2.did()],
    handle,
    pds: atpPds,
    prev: null,
    signer: rotationKey1,
  });
  ops.push(createOp);
  signingKeys.push(0n);

  let did = await didForCreateOp(createOp);
  binaryDid = getBinaryDid(did);
  return {
    history: ops.map((op) => hexFrom(cbor.encode(op))),
    signingKeys,
    binaryDid,
    keyPairs: [rotationKey1, rotationKey1],
  };
}

export async function signDidWeb5(
  result: PlcResult,
  signingKey: number,
  msg: Hex,
): Promise<void> {
  let keypair = result.keyPairs[signingKey];
  let signature = await keypair.sign(bytesFrom(msg));
  result.sig = hexFrom(signature);
  result.signingKeys.push(numFrom(signingKey));
  console.assert(result.signingKeys.length == result.history.length + 1);
}
