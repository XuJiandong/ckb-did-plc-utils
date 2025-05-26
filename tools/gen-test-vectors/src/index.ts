import * as cbor from "@ipld/dag-cbor";
import { check } from "@atproto/common";
import {
  P256Keypair,
  Secp256k1Keypair,
  parseDidKey,
  p256Plugin,
  secp256k1Plugin,
} from "@atproto/crypto";
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

// Parse command line arguments
const args = process.argv.slice(2);
const noRandom = args.includes("--no-random");
const enableLog = args.includes("--enable-log");

if (noRandom) {
  console.log("Running with deterministic keys (--no-random mode)");
}

const FIXED_SECP256K1_PRIVATE_KEY = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
]);

const FIXED_P256_PRIVATE_KEY = new Uint8Array([
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
  0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
  0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
]);

async function createSecp256k1Keypair(index = 0): Promise<Secp256k1Keypair> {
  if (noRandom) {
    const privateKey = new Uint8Array(FIXED_SECP256K1_PRIVATE_KEY);
    privateKey[0] = (privateKey[0] + index) % 256;
    return Secp256k1Keypair.import(privateKey);
  } else {
    return Secp256k1Keypair.create();
  }
}

async function createP256Keypair(): Promise<P256Keypair> {
  if (noRandom) {
    return P256Keypair.import(FIXED_P256_PRIVATE_KEY);
  } else {
    return P256Keypair.create();
  }
}

async function writeFile(name: string, op: CompatibleOpOrTombstone) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  let filePath = path.join(__dirname, "../test-vectors/" + name + ".cbor");
  let cborBinary = cbor.encode(op);
  writeFileSync(filePath, cborBinary);
  console.log(`test vector (${name}) written to ${filePath}`);
}

async function writeDidFile(name: string, did: string) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  let filePath = path.join(__dirname, "../test-vectors/" + name + ".did");
  writeFileSync(filePath, did);
  console.log(`DID (${did}) written to ${filePath}`);
}

function dumpOperationMeta(msg: string, prevOp: Operation, op: Operation) {
  if (!enableLog) {
    return;
  }
  console.log(msg);
  console.log("prev: ", op.prev);

  let unsignedOp = structuredClone(op);
  delete (unsignedOp as any).sig;
  console.assert(
    check.is(unsignedOp, def.unsignedOperation),
    "unsignedOp is not valid",
  );
  let cborData = Buffer.from(cbor.encode(unsignedOp));
  console.log(
    `unsigned operation: (length = ${cborData.length}) ${cborData.toString("hex")}`,
  );

  for (let key of prevOp.rotationKeys) {
    console.log("rotation key: ", key);

    const parsed = parseDidKey(key);
    let plugins = [p256Plugin, secp256k1Plugin];
    const plugin = plugins.find((p) => p.jwtAlg === parsed.jwtAlg);
    if (!plugin) {
      throw new Error(`Unsupported signature alg: ${parsed.jwtAlg}`);
    }
    const pubkey = plugin.compressPubkey(parsed.keyBytes);
    console.log(
      `pubkey: ${plugin.jwtAlg}, (length = ${pubkey.length}) ${Buffer.from(pubkey).toString("hex")}`,
    );
  }
  let sig = op.sig;
  let sigBuf = Buffer.from(sig, "base64url");
  console.log(`sig: (length = ${sigBuf.length}) ${sigBuf.toString("hex")}`);
}

// test vectors from: https://github.com/did-method-plc/did-method-plc/blob/main/packages/lib/tests/data.test.ts
async function main() {
  let ops: CompatibleOpOrTombstone[] = [];
  let did: string;
  let handle = "at://alice.example.com";
  let atpPds = "https://example.com";
  let signingKey = await createSecp256k1Keypair(0);
  let rotationKey1 = await createSecp256k1Keypair(1);
  let rotationKey2 = await createP256Keypair();

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
    await writeFile("1-did-creation", createOp);
    writeDidFile("creation", did);
  }

  {
    const noPrefix = "alice.example2.com";
    handle = `at://${noPrefix}`;
    const op = await updateHandleOp(
      lastOp() as Operation,
      rotationKey1,
      noPrefix,
    );
    ops.push(op);
    await writeFile("2-update-handle", op);
  }
  dumpOperationMeta(
    "1 --> 2",
    ops.at(-2) as Operation,
    ops.at(-1) as Operation,
  );

  {
    const noPrefix = "example2.com";
    atpPds = `https://${noPrefix}`;
    const op = await updatePdsOp(lastOp() as Operation, rotationKey1, noPrefix);
    ops.push(op);
    await writeFile("3-update-pds", op);
  }

  {
    const newSigningKey = await createSecp256k1Keypair(2);
    const op = await updateAtprotoKeyOp(
      lastOp() as Operation,
      rotationKey1,
      newSigningKey.did(),
    );
    ops.push(op);
    await writeFile("4-update-atproto-key", op);
    signingKey = newSigningKey;
  }

  {
    const newRotationKey = await createSecp256k1Keypair(3);
    const op = await updateRotationKeysOp(lastOp() as Operation, rotationKey1, [
      newRotationKey.did(),
      rotationKey2.did(),
    ]);
    ops.push(op);

    rotationKey1 = newRotationKey;
    await writeFile("5-update-rotation-keys", op);
  }

  {
    const newHandle = "at://ali.example.com";
    const op = await updateHandleOp(
      lastOp() as Operation,
      rotationKey2,
      newHandle,
    );
    ops.push(op);
    handle = newHandle;
    await writeFile("6-update-handle", op);
  }

  {
    const last = await getLastOpWithCid(ops);
    const op = await tombstoneOp(last.cid, rotationKey1);
    // ops.push(op);
    await writeFile("7-tombstone", op);
  }

  // finally verify all operations
  const doc = await validateOperationLog(did, ops);
  verifyDoc(doc);

  // ---------- legacy operations -----------
  ops = [];
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
    ops.push(legacyOp);
    await writeFile("1-did-creation-legacy", legacyOp);
    writeDidFile("creation-legacy", did);
  }

  {
    const op = await updateRotationKeysOp(lastOp() as Operation, rotationKey2, [
      rotationKey1.did(),
      rotationKey2.did(),
    ]);
    ops.push(op);
    await writeFile("2-update-rotation-keys-legacy", op);
  }
  // finally verify all operations
  const doc2 = await validateOperationLog(did, ops);
  verifyDoc(doc2);
}

(() => {
  main();
})();
