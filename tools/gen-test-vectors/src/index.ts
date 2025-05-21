import * as cbor from "@ipld/dag-cbor";
import { check } from "@atproto/common";
import { P256Keypair, Secp256k1Keypair } from "@atproto/crypto";
import {
  atprotoOp,
  Operation,
  def,
  didForCreateOp,
  updateHandleOp,
  updatePdsOp,
  updateAtprotoKeyOp,
  updateRotationKeysOp,
  validateOperationLog,
  DocumentData,
  deprecatedSignCreate,
  tombstoneOp,
  getLastOpWithCid,
  CompatibleOpOrTombstone,
} from "@did-plc/lib";
import { writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

async function writeFile(name: string, op: CompatibleOpOrTombstone) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  let filePath = path.join(__dirname, "../test-vectors/" + name + ".cbor");
  let cborBinary = cbor.encode(op);
  writeFileSync(filePath, cborBinary);
  console.log(`test vector (${name}) written to ${filePath}`);
}

// test vectors from: https://github.com/did-method-plc/did-method-plc/blob/main/packages/lib/tests/data.test.ts
async function main() {
  const ops: Operation[] = [];
  let did: string;
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let oldRotationKey1: Secp256k1Keypair;
  let signingKey = await Secp256k1Keypair.create();
  let rotationKey1 = await Secp256k1Keypair.create();
  let rotationKey2 = await P256Keypair.create();

  const lastOp = () => {
    const lastOp = ops.at(-1);
    if (!lastOp) {
      throw new Error("expected an op on log");
    }
    return lastOp;
  };

  const verifyDoc = (doc: DocumentData | null) => {
    if (!doc) {
      throw new Error("expected doc");
    }
    console.assert(doc.did === did, "did mismatch");
    console.assert(
      doc.verificationMethods.atproto === signingKey.did(),
      "atproto verification method mismatch",
    );
    console.assert(
      doc.rotationKeys.length === 2,
      "rotation keys length mismatch",
    );
    console.assert(
      doc.rotationKeys.includes(rotationKey1.did()),
      "rotation key 1 mismatch",
    );
    console.assert(
      doc.rotationKeys.includes(rotationKey2.did()),
      "rotation key 2 mismatch",
    );
    console.assert(doc.alsoKnownAs.length === 1, "alsoKnownAs length mismatch");
    console.assert(doc.alsoKnownAs[0] === handle, "handle mismatch");
  };

  {
    const createOp = await atprotoOp({
        signingKey: signingKey.did(),
        rotationKeys: [rotationKey1.did(), rotationKey2.did()],
        handle,
        pds: atpPds,
        prev: null,
        signer: rotationKey1,
      });
      console.assert(check.is(createOp, def.operation), "createOp is not valid");
      ops.push(createOp);
      did = await didForCreateOp(createOp);
      await writeFile("did-creation", createOp);
  }

  {
    const noPrefix = "ali.exampl2.com";
    handle = `at://${noPrefix}`;
    const op = await updateHandleOp(lastOp(), rotationKey1, noPrefix);
    ops.push(op);
    await writeFile("update-handle", op);
  }

  {
    const noPrefix = "example2.com";
    atpPds = `https://${noPrefix}`;
    const op = await updatePdsOp(lastOp(), rotationKey1, noPrefix);
    ops.push(op);
    await writeFile("update-pds", op);
  }

  {
    const newSigningKey = await Secp256k1Keypair.create();
    const op = await updateAtprotoKeyOp(
      lastOp(),
      rotationKey1,
      newSigningKey.did(),
    );
    ops.push(op);
    await writeFile("update-atproto-key", op);
    signingKey = newSigningKey;
  }

  {
    const newRotationKey = await Secp256k1Keypair.create();
    const op = await updateRotationKeysOp(lastOp(), rotationKey1, [
      newRotationKey.did(),
      rotationKey2.did(),
    ]);
    ops.push(op);

    oldRotationKey1 = rotationKey1;
    rotationKey1 = newRotationKey;
    await writeFile("update-rotation-keys", op);
  }

  {
    const newHandle = "at://ali.example.com";
    const op = await updateHandleOp(lastOp(), rotationKey2, newHandle);
    ops.push(op);
    handle = newHandle;
    await writeFile("update-handle", op);
  }

  // finally verify all operations
  const doc = await validateOperationLog(did, ops);
  verifyDoc(doc);

  // tombstone operation
  {
    const last = await getLastOpWithCid(ops);
    const op = await tombstoneOp(last.cid, rotationKey1);
    await writeFile("tombstone", op);
  }

  // legacy operation (creation)
  {
    const legacyOp = await deprecatedSignCreate(
      {
        type: "create",
        signingKey: signingKey.did(),
        recoveryKey: rotationKey2.did(),
        handle,
        service: atpPds,
        prev: null,
      },
      signingKey,
    );
    did = await didForCreateOp(legacyOp);
    await writeFile("did-creation-legacy", legacyOp);
  }
}

(() => {
  main();
})();
