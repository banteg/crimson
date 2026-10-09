// A strict reader for the replay payload's msgpack subset (docs/formats/replay.md, "Envelope").
//
// The payload must be canonical: one byte string per value. Rather than decode and re-encode, the reader refuses
// every encoding the canonical writer (msgspec) never produces, so a payload it accepts is the only encoding of its
// value: the shortest header for every integer, string, array and map, float64 for every float, and no bin or ext.
// Maps keep their key order, which the schema checks. A reader yields one token at a time, so a caller can decode a
// long array into its own form rather than a value per element.

export type Scalar = null | boolean | number | F64 | string;
export type Value = Scalar | Value[] | MapValue;
// float64 values stay apart from integers: an integer in a float field, or the reverse, is not canonical.
export class F64 {
  constructor(readonly value: number) {}
}
export class MapValue {
  constructor(readonly entries: [string, Value][]) {}
}

// An array or map's header; its elements follow.
export class Head {
  constructor(
    readonly kind: "array" | "map",
    readonly length: number,
  ) {}
}

export class PayloadError extends Error {}

// ignoreBOM keeps a leading U+FEFF in the string, as msgspec does.
const textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class Reader {
  offset = 0;
  private readonly view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get done(): boolean {
    return this.offset === this.bytes.length;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  value(): Value {
    const token = this.token();
    if (!(token instanceof Head)) return token;
    return token.kind === "array" ? this.array(token.length) : this.map(token.length);
  }

  // A map's key.
  key(): string {
    const key = this.value();
    if (typeof key !== "string") throw new PayloadError("map key is not a string");
    return key;
  }

  // The next float64's value, or undefined, reading nothing, when the next value is another kind.
  float64(): number | undefined {
    if (this.bytes[this.offset] !== 0xcb) return undefined;
    return this.view.getFloat64(this.take(9) + 1, false);
  }

  token(): Scalar | Head {
    const byte = this.u8();
    if (byte <= 0x7f) return byte;
    if (byte >= 0xe0) return byte - 0x100;
    if (byte >= 0x80 && byte <= 0x8f) return new Head("map", byte & 0x0f);
    if (byte >= 0x90 && byte <= 0x9f) return new Head("array", byte & 0x0f);
    if (byte >= 0xa0 && byte <= 0xbf) return this.str(byte & 0x1f);
    switch (byte) {
      case 0xc0:
        return null;
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xcb:
        return new F64(this.view.getFloat64(this.take(8), false));
      case 0xcc:
        return this.unsigned(this.u8(), 0x80);
      case 0xcd:
        return this.unsigned(this.view.getUint16(this.take(2), false), 0x100);
      case 0xce:
        return this.unsigned(this.view.getUint32(this.take(4), false), 0x10000);
      case 0xcf: {
        const value = this.view.getBigUint64(this.take(8), false);
        if (value < 0x100000000n) throw new PayloadError("non-minimal uint64");
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new PayloadError("integer out of range");
        return Number(value);
      }
      case 0xd0:
        return this.signed(this.view.getInt8(this.take(1)), -0x20);
      case 0xd1:
        return this.signed(this.view.getInt16(this.take(2), false), -0x80);
      case 0xd2:
        return this.signed(this.view.getInt32(this.take(4), false), -0x8000);
      case 0xd3: {
        const value = this.view.getBigInt64(this.take(8), false);
        if (value >= -0x80000000n) throw new PayloadError("non-minimal int64");
        if (value < BigInt(Number.MIN_SAFE_INTEGER)) throw new PayloadError("integer out of range");
        return Number(value);
      }
      case 0xd9:
        return this.str(this.length(this.u8(), 0x20));
      case 0xda:
        return this.str(this.length(this.view.getUint16(this.take(2), false), 0x100));
      case 0xdb:
        return this.str(this.length(this.view.getUint32(this.take(4), false), 0x10000));
      case 0xdc:
        return new Head("array", this.length(this.view.getUint16(this.take(2), false), 0x10));
      case 0xdd:
        return new Head("array", this.length(this.view.getUint32(this.take(4), false), 0x10000));
      case 0xde:
        return new Head("map", this.length(this.view.getUint16(this.take(2), false), 0x10));
      case 0xdf:
        return new Head("map", this.length(this.view.getUint32(this.take(4), false), 0x10000));
      case 0xca:
        throw new PayloadError("float32 instead of float64");
      default:
        throw new PayloadError(`unsupported msgpack type 0x${byte.toString(16)}`);
    }
  }

  private u8(): number {
    return this.bytes[this.take(1)]!;
  }

  private take(count: number): number {
    const at = this.offset;
    if (at + count > this.bytes.length) throw new PayloadError("truncated payload");
    this.offset += count;
    return at;
  }

  // Non-negative integers use the smallest unsigned form; `minimum` is the first value the form is needed for.
  private unsigned(value: number, minimum: number): number {
    if (value < minimum) throw new PayloadError("non-minimal unsigned integer");
    return value;
  }

  // Negative integers use the smallest signed form; `maximum` is the largest value the form is needed for.
  private signed(value: number, maximum: number): number {
    if (value >= 0) throw new PayloadError("non-negative integer in a signed form");
    if (value >= maximum) throw new PayloadError("non-minimal signed integer");
    return value;
  }

  private length(value: number, minimum: number): number {
    if (value < minimum) throw new PayloadError("non-minimal length header");
    return value;
  }

  private str(length: number): string {
    const at = this.take(length);
    try {
      return textDecoder.decode(this.bytes.subarray(at, at + length));
    } catch {
      throw new PayloadError("string is not UTF-8");
    }
  }

  private array(length: number): Value[] {
    const items: Value[] = [];
    for (let i = 0; i < length; i++) items.push(this.value());
    return items;
  }

  private map(length: number): MapValue {
    const entries: [string, Value][] = [];
    for (let i = 0; i < length; i++) entries.push([this.key(), this.value()]);
    return new MapValue(entries);
  }
}
