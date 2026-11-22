// Compile-time check of the SigningMessage brand of @sbtp/wasm. Never run, only type-checked: see
// README.md in this directory.
import { signingMessage, SigningMessage } from "@sbtp/wasm";

declare function signer(message: SigningMessage): void;
declare const block: Uint8Array;

// A message from the typed builder is accepted.
signer(signingMessage(block));

// @ts-expect-error a Uint8Array is not a SigningMessage
signer(new Uint8Array(49));

// @ts-expect-error an object with the same public members is not a SigningMessage
signer({ bytes: new Uint8Array(49), kind: "block", free() {}, [Symbol.dispose]() {} });

// @ts-expect-error there is no public constructor
new SigningMessage();
