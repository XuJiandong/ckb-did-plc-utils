import { Keypair, P256Keypair, Secp256k1Keypair } from "@atproto/crypto";
import {
  atprotoOp,
  didForCreateOp,
  Operation,
  updateHandleOp,
  updateRotationKeysOp,
} from "@did-plc/lib";
import * as cbor from "@ipld/dag-cbor";

import * as uint8arrays from "uint8arrays";
import { bytesFrom, Hex, hexFrom, Num, numFrom } from "@ckb-ccc/core";

function getBinaryDid(did: string): Hex {
  if (!did.startsWith("did:plc:")) {
    throw new Error("Invalid DID");
  }
  const didWithoutPrefix = did.slice(8);
  const decoded = uint8arrays.fromString(didWithoutPrefix, "base32");
  return hexFrom(decoded);
}

export type PlcOperationResult = {
  history: Hex[];
  signingKeys: Num[];
  binaryDid: Hex;
  keyPairs: Keypair[];
  sig?: Hex;
};

export async function generateOperations(config?: {
  moreOps?: boolean;
  invalidSignature?: boolean;
  mismatchedHistory?: boolean;
  key?: Secp256k1Keypair;
  rotationKey1?: Secp256k1Keypair;
  rotationKey2?: P256Keypair;
}): Promise<PlcOperationResult> {
  const ops: Operation[] = [];
  const key = config?.key ?? (await Secp256k1Keypair.create());
  const rotationKey1 =
    config?.rotationKey1 ?? (await Secp256k1Keypair.create());
  const rotationKey2 = config?.rotationKey2 ?? (await P256Keypair.create());
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let binaryDid: Hex = "0x";
  let signingKeys: Num[] = [];

  const lastOp = () => {
    const op = ops.at(-1);
    if (!op) {
      throw new Error("can't find last op");
    }
    return op;
  };
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

  if (config?.moreOps || config?.invalidSignature) {
    // update handle
    handle = "at://ali.example2.com";
    const op = await updateHandleOp(lastOp(), rotationKey1, handle);
    ops.push(op);
    signingKeys.push(0n);

    // update with r1 key
    const op2 = await updateHandleOp(lastOp(), rotationKey2, handle);
    ops.push(op2);
    signingKeys.push(1n);

    // update rotation keys
    const newRotationKey = await Secp256k1Keypair.create();
    let op3 = await updateRotationKeysOp(lastOp(), rotationKey1, [
      rotationKey1.did(),
      rotationKey2.did(),
      newRotationKey.did(),
    ]);
    if (config?.invalidSignature) {
      let wrongSig = uint8arrays.fromString(op3.sig, "base64url");
      wrongSig[0] ^= 1;
      op3.sig = uint8arrays.toString(wrongSig, "base64url");
    }
    ops.push(op3);
    signingKeys.push(0n);
  }
  if (config?.mismatchedHistory) {
    ops.pop();
  }
  return {
    history: ops.map((op) => hexFrom(cbor.encode(op))),
    signingKeys,
    binaryDid,
    keyPairs: [rotationKey1, rotationKey2],
  };
}

export async function signDidWeb5(
  result: PlcOperationResult,
  signingKey: number,
  msg: Hex,
): Promise<void> {
  let keypair = result.keyPairs[signingKey];
  let signature = await keypair.sign(bytesFrom(msg));
  result.sig = hexFrom(signature);
  result.signingKeys.push(numFrom(signingKey));
}
