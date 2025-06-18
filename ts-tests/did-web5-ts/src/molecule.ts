import {
  mol,
  HexLike,
  hexFrom,
  Hex,
  NumLike,
  numFrom,
  Num,
} from "@ckb-ccc/core";

// table DidWeb5DataV1 {
//     document: Bytes,
//     transferredFrom: StringOpt,
// }
export type DidWeb5DataV1Like = {
  document: HexLike;
  transferredFrom?: HexLike | null;
};

@mol.codec(
  mol.table({
    document: mol.Bytes,
    transferredFrom: mol.BytesOpt,
  }),
)
export class DidWeb5DataV1 extends mol.Entity.Base<
  DidWeb5DataV1Like,
  DidWeb5DataV1
>() {
  constructor(
    public document: Hex,
    public transferredFrom?: Hex,
  ) {
    super();
  }

  static from(data: DidWeb5DataV1Like): DidWeb5DataV1 {
    if (data instanceof DidWeb5DataV1) {
      return data;
    }
    return new DidWeb5DataV1(
      hexFrom(data.document),
      data.transferredFrom ? hexFrom(data.transferredFrom) : undefined,
    );
  }
}

// union DidWeb5Data {
//   DidWeb5DataV1,
// }

export type DidWeb5DataLike = {
  value: DidWeb5DataV1Like;
};

@mol.codec(
  mol.union({
    DidWeb5DataV1,
  }),
)
export class DidWeb5Data extends mol.Entity.Base<
  DidWeb5DataLike,
  DidWeb5Data
>() {
  constructor(
    public type: "DidWeb5DataV1",
    public value: DidWeb5DataV1,
  ) {
    super();
  }

  static from(data: DidWeb5DataLike): DidWeb5Data {
    if (data instanceof DidWeb5Data) {
      return data;
    }
    return new DidWeb5Data("DidWeb5DataV1", DidWeb5DataV1.from(data.value));
  }
}

// table PlcAuthorization {
//     history: BytesVec,
//     sig: Bytes,
//     signingKeys: Uint8Vec,
// }
export type PlcAuthorizationLike = {
  history: HexLike[];
  sig: HexLike;
  signingKeys: NumLike[];
};

@mol.codec(
  mol.table({
    history: mol.BytesVec,
    sig: mol.Bytes,
    signingKeys: mol.Uint8Vec,
  }),
)
export class PlcAuthorization extends mol.Entity.Base<
  PlcAuthorizationLike,
  PlcAuthorization
>() {
  constructor(
    public history: Hex[],
    public sig: Hex,
    public signingKeys: Num[],
  ) {
    super();
  }

  static from(data: PlcAuthorizationLike): PlcAuthorization {
    if (data instanceof PlcAuthorization) {
      return data;
    }
    return new PlcAuthorization(
      data.history.map((h) => hexFrom(h)),
      hexFrom(data.sig),
      data.signingKeys.map((s) => numFrom(s)),
    );
  }
}

// table DidWeb5Witness {
//   transferredFrom: PlcAuthorization,
// }

export type DidWeb5WitnessLike = {
  transferredFrom: PlcAuthorizationLike;
};

@mol.codec(
  mol.table({
    transferredFrom: PlcAuthorization,
  }),
)
export class DidWeb5Witness extends mol.Entity.Base<
  DidWeb5WitnessLike,
  DidWeb5Witness
>() {
  constructor(public transferredFrom: PlcAuthorization) {
    super();
  }

  static from(data: DidWeb5WitnessLike): DidWeb5Witness {
    if (data instanceof DidWeb5Witness) {
      return data;
    }
    return new DidWeb5Witness(PlcAuthorization.from(data.transferredFrom));
  }
}
