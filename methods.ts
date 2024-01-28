import {
  HasherAndAlgorithm,
  KeyBinding,
  SdJwtVc,
  SignatureAndEncryptionAlgorithm,
} from "@sd-jwt/core";
import crypto from "crypto";

const { publicKey: issuerPublicKey, privateKey: issuerPrivateKey } =
  crypto.generateKeyPairSync("ed25519");

const { publicKey: holderPublicKey, privateKey: holderPrivateKey } =
  crypto.generateKeyPairSync("ed25519");

const hasherAndAlgorithm: HasherAndAlgorithm = {
  algorithm: "sha-256",
  hasher: (data, algorithm) =>
    crypto.createHash(algorithm).update(data).digest(),
};

export async function sign() {
  const compact = await new SdJwtVc(
    {
      header: {
        typ: "vc+sd-jwt",
        alg: SignatureAndEncryptionAlgorithm.EdDSA,
        // We set the issuer key in the header.
        // if you use dids, you'd include the relative kid here (#key-1)
        jwk: issuerPublicKey.export({ format: "jwk" }),
      },
      payload: {
        // VCT is required
        vct: "TravelBadge",
        // iat is required
        iat: Math.floor(new Date().getTime() / 1000),
        name: "Belsy",
        countriesVisited: {
          usa: true,
          netherlands: true,
          laos: false,
          thailand: true,
        },
        // Include holder jwk in cnf, allowing to do key binding
        cnf: {
          jwk: holderPublicKey.export({
            format: "jwk",
          }),
        },
        // You need to set the `iss` claim. It can be a did, and url, or
        // e.g. a JWK thumbprint, as long as it's an URI. For now using a random
        // URL. If it's an HTTPS URI it MUST point to some issuer metadata
        // as described here: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#name-obtaining-public-key-for-is
        iss: "https://issuer.com",
      },
    },
    {
      saltGenerator: () =>
        crypto.getRandomValues(Buffer.alloc(16)).toString("base64url"),
      hasherAndAlgorithm,
      disclosureFrame: {
        name: true,
        // Allow all countries to be separately disclosed
        // Except, thailand, that is ALWAYS disclosed
        countriesVisited: {
          usa: true,
          netherlands: true,
          laos: true,
          thailand: false, // can also omit
        },
      },
      signer: (input) =>
        crypto.sign(null, Buffer.from(input), issuerPrivateKey),
    }
  ).toCompact();

  return compact;
}

export async function verify(compact: string) {
  const sdJwtVc = SdJwtVc.fromCompact(compact);

  return sdJwtVc.verify(({ message, signature, publicKeyJwk, header }) => {
    const jwk =
      publicKeyJwk ?? (header.jwk as Record<string, unknown> | undefined);

    if (!jwk) {
      throw new Error("Missing public key jwk");
    }

    const publicKey = crypto.createPublicKey({
      format: "jwk",
      key: jwk,
    });

    return crypto.verify(null, Buffer.from(message), publicKey, signature);
  });
}

export async function prove(
  compact: string,
  presentationFrame: Record<string, unknown>,
  verifier: {
    aud: string;
    nonce: string;
  }
) {
  const sdJwtVc = SdJwtVc.fromCompact(compact).withHasher(hasherAndAlgorithm);

  const withRemovedDisclosures = await sdJwtVc.present(
    presentationFrame as any
  );

  // Add keybinding JWT to the SD-JWT-VC (to prove we are the holder)
  sdJwtVc.withKeyBinding(
    await new KeyBinding(
      {
        header: {
          alg: SignatureAndEncryptionAlgorithm.EdDSA,
          typ: "kb+jwt",
        },
        // aud and nonce are REQUIRED for presentation
        // what the values must be is unspecified and depends on exchange protocol
        // but aud should identify the verifier
        payload: {
          aud: verifier.aud,
          nonce: verifier.nonce,
          iat: Math.floor(new Date().getTime() / 1000),
          // We must include a hash of the SD-JWT-VC with the disclosures we are presenting
          // to ensure integrity. This will be added to the sd-jwt library in a future version
          _sd_hash: crypto
            .createHash("sha256")
            .update(withRemovedDisclosures)
            .digest("base64url"),
        },
      },
      {
        signer: (input) =>
          crypto.sign(null, Buffer.from(input), holderPrivateKey),
      }
    ).toCompact()
  );

  // Return the presentation. We have to call present twice now as we need to sd-jwt without only disclosures to calculate _sd_hash for kb-jwt.
  // once this is added to the library we can remove the twice present call.
  return sdJwtVc.present(presentationFrame as any);
}

export async function getDecodedSdJwtVc(compact: string) {
  const sdJwtVc = SdJwtVc.fromCompact(compact).withHasher(hasherAndAlgorithm);

  return {
    compact: compact,
    prettyClaims: await sdJwtVc.getPrettyClaims(),
    signedPayload: sdJwtVc.payload,
    header: sdJwtVc.header,
    disclosures: await sdJwtVc.disclosuresWithDigest(),
    keyBinding: sdJwtVc.keyBinding
      ? {
          compact: await sdJwtVc.keyBinding.toCompact(),
          signedPayload: sdJwtVc.keyBinding.payload,
          header: sdJwtVc.keyBinding.header,
        }
      : undefined,
  };
}
