import { getDecodedSdJwtVc, prove, sign, verify } from "./methods";

async function run() {
  const compact = await sign();
  console.log(
    "created compact SD-JWT-VC",
    JSON.stringify(
      {
        compact,
        decoded: await getDecodedSdJwtVc(compact),
      },
      null,
      2
    )
  );

  // Verify (no key binding JWT yet, so it won't verify that)
  // You can check this by checking if the keyBinding verification is present
  // in the verification object (if not, there was no key binding)
  const verificationResult = await verify(compact);
  console.log("verified compact SD-JWT-VC", {
    verificationResult,
  });

  // Present name, and countriesVisited.netherlands
  // All required disclosures (such as countriesVisited.thailand) will ALWAYS be disclosed
  const presentation = await prove(
    compact,
    {
      name: true,
      countriesVisited: {
        netherlands: true,
      },
    },
    {
      aud: "https://verifier.com",
      nonce: "1234",
    }
  );

  console.log(
    "created presentation SD-JWT-VC",
    JSON.stringify(
      {
        presentation,
        decoded: await getDecodedSdJwtVc(presentation),
      },
      null,
      2
    )
  );

  // Verify presentation
  const presentationVerificationResult = await verify(presentation);
  console.log(
    "verified presentation SD-JWT-VC",
    presentationVerificationResult
  );
}

run();
