# PKI Validation Procedures

The following procedures shall be applied when validating a barcode against the PKI.

## Overall Validation

Input: `barcodeData` of type `BarcodeHeader`

1. If `barcodeData.contents` is of the variety `unsigned`, return
     `SUCCESS(UNSIGNED, [sequence of data elements from barcodeData.contents.unsigned], [])`; otherwise:
2. Let `deviceData` be `barcodeData.contents.signed.data`.
3. Let `eeCert` be `deviceData.certificate`.
4. Validate that the `eeCert` has not expired. If it has, output `CERTIFICATE-EXPIRED`.
5. If any extension in `eeCert` is not known to the validator, and is marked critical, output `INVALID-CERTIFICATE-CHAIN`.
6. Let `issuingCa` be the X.509 certificate looked up by the key `(eeCert.issuingSecurityProvider, eeCert.caId)`.
    The corresponding certificate is that with the matching values in its `certificateIdExt` extension.
    If a certificate cannot be found, return `UNKNOWN-SIGNING-CERTIFICATE`.
7. Fetch the End-Entity Certificate Revocation List specified in the `eeCertCRLExt` extension of `issuingCa`.
    This may either be retrieved over the network, or (recommended) pulled from cache.
    If such an extension does not exist, return `INVALID-CERTIFICATE-CHAIN`.
8. Verify that `eeCert.serial` does not appear on the revocation list.
    If it does, output `CERTIFICATE-REVOKED`.
9. Perform standard X.509 chain building from the `issuingCa` to an acceptable root certificate,
    making sure CA constraints, path length constraints, revocation status, etc. validate along the
    whole chain.
    Let `certChain` be the ordered list of certificates in the validated chain, starting from the root and
    ending at the `issuingCa`.
    If such a chain cannot be built, return `CERTIFICATE-EXPIRED`, `CERTIFICATE-REVOKED`, or
    `INVALID-CERTIFICATE-CHAIN`, as appropriate.
10. Let `eePubKey` be the reconstructed public key according to SEC 4 using `eeCert.publicKeyReconstructionData` and
     the `issuingCa`'s public key. If the curve types do not match, return `INVALID-CERTIFICATE-CHAIN`.
11. Perform the EC-KNR decapsulation on `deviceData.data` using the `eePubKey`.
12. Let `issuerData` be the C-APER decoding of the decapsulated data. If the ASN.1 decoding fails,
     return `INVALID`.
13. If `issuerData.endOfValidity` is not none, and is in the past, return `EXPIRED`.
14. If `issuerData.deviceBinding` is not none, perform the 'Device Data Validation' procedure 
     with inputs of `barcodeData` and `issuerData.deviceBinding`, returning any error it outputs.
     Let `deviceDataElements` be the output of this procedure.
15. If `issuerData.deviceBinding` is none, and `barcodeData.contents.signed.deviceSignature` is not none,
     return `INVALID`; otherwise let `deviceDataElements` be the empty list `[]`.
16. Let `issuerDataElements` be `[sequence of data elements from issuerData.data]`)
17. For each `dataElement` in `issuerDataElements`, let `object` be the `DATA-ELEMENT` object for 
      `dataElement.format` in the object set `IssuerDataElements`.
    1. If the format is unknown or unsupported, and `dataElement.critical` is TRUE, return `INVALID`.
    2. Otherwise, continue, ignoring this data element.
18. Starting at the root CA in `certChain`, and ending with the `eeCert`, if the certificate contains the 
     `issuerDataAuthorizationExt` extension, perform the 'Data Authorization Validation' procedure
     with inputs of `issuerDataElements`, the decoded extension value, and `IssuerDataElements`, returning any error it outputs.
     If the extension cannot be decoded, return `INVALID-CERTIFICATE-CHAIN`.
19. If `eeCert`, or any cert in `certChain`, contains the `specimenPoisonExt`, return `SUCCESS(SPECIMEN, issuerDataElements, deviceDataElements)`
20. Otherwise, output `SUCCESS(VALID, issuerDataElements, deviceDataElements)`

## Device Data Validation

Input: `barcodeData` of type `BarcodeHeader`, `deviceBinding` of type `IssuerSignedData.deviceBinding`.

1. Let `deviceDataBytes` be C-APER encoding of `barcodeData.contents.signed.data`.
2. If `barcodeData.contents.signed.deviceSignature` is unset, return `INVALID`.
3. Verify `barcodeData.contents.signed.deviceSignature` is a valid signature over `deviceDataBytes`
    using the public key `deviceBinding.level2PublicKey`. If it is not, return `INVALID`.
4. If `barcodeData.contents.signed.data.timestamp` is none, return `INVALID`.
5. If `barcodeData.contents.signed.data.timestamp` plus `deviceBinding.validityDuration` is in the past,
     return `EXPIRED`.
6. Return `SUCCESS([sequence of data elements from barcodeData.contents.signed.data.deviceData])`

## Data Authorization Validation

Input: `dataElements`, a sequence of `Data`, and `authorisation` of type `DataAuthorization`, and `set` be an object set.

1. If authorisation contains more than one entry with the same `format`, return `INVALID-CERTIFICATE-CHAIN`.
2. For each `dataElement` in `dataElements`:
   1. Let `authorizationEntry` be the entry in `authorisation` whose `format` is equal to `dataElement.format`.
       If no such entry exists, return `INVALID`.
   2. Let `object` be the `DATA-ELEMENT` object for `dataElement.format` in the `set`.
      1. If the format is unknown or unsupported, and it is critical, return `INVALID`.
      2. Otherwise, continue without validating its format-specific constraint.
   3. Decode `dataElement.value` as `object.&Type` using `object.&encoding`.
       If decoding fails, return `INVALID`.
   4. Decode `authorizationEntry.constraint` as `object.&CertificateConstraint` using `object.&encoding`.
       If decoding fails, return `INVALID-CERTIFICATE-CHAIN`.
   5. Perform the certificate-constraint validation procedure specified by object with the decoded data 
       element and decoded constraint as inputs, returning any error.
3. If nothing has failed, return `SUCCESS`.

## Multi-Modal Ticket Authorization Validation

This procedure is the certificate-constraint validation procedure for the `MMT1` data element.

Input: `ticket` of type `MultiModalTicket`, `constraints` of type `MultiModalTicketConstraints`.

1. If `ticket.issuingDetail.issuer` is present, let `effectiveIssuer` be its value, otherwise let it be `eeCert.issuingSecurityProvider`.
2. If `constraints.issuer` is present and `effectiveIssuer` does not appear in `constraints.issuer`, return `INVALID`.
3. If `constraints.securePaperTicket` is present and `ticket.issuingDetail.securePaperTicket` is not equal to it, return `INVALID`.
4. If `constraints.mandatoryOnlineValidation` is TRUE, and `ticket.controlData.onlineValidationRequired` not `mandatory`,
     or `ticket.controlData.onlineValidationType` is unset, return `INVALID`.
5. If `ticket.issuingDetail.extension` is present:
   1. If `constraints.issuingExtensions` is absent, continue.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `ticket.issuingDetail.extension`,
       `constraints.issuingExtensions`, and `IssuingDataExtensions`, returning any error.
6. If `ticket.controlData.extension` is present:
   1. If `constraints.controlExtensions` is absent, continue.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `ticket.controlData.extension`,
       `constraints.controlExtensions`, and `ControlDataExtensions`, returning any error.
7. For every effective carrier for which any document in the ticket grants or extends an entitlement:
   1. If `constraints.carriers` is present and the carrier is not included, return `INVALID`.
   2. In case of `excludedCarrier`, the base set from which it excludes is the intersection of all 
       `constraints.carriers` on all certificates in the chain.
8. For every effective service brand for which any document in the ticket grants or extends an entitlement:
   1. If `constraints.serviceBrands` is present and the service brand is not contained in it, return `INVALID`.
   2. In case of `excludedServiceBrand`, the base set from which it excludes is the intersection of all 
       `constraints.serviceBrands` on all certificates in the chain.
9. For every effective transport type for which any document in the ticket grants or extends an entitlement:
   1. If `constraints.transportTypes` is present and the transport type is not contained in it, return `INVALID`.
   2. In case of `excludedTransportTypes`, the base set from which it excludes is the intersection of all 
       `constraints.transportTypes` on all certificates in the chain.
10. For every `Product` occurring in the ticket:
    1. Resolve its effective `productOwner`, including inheritance from the applicable general conditions and issuer.
    2. If `constraints.products` is present, at least one `ProductRestriction` in it **MUST** match the product.
        A ProductRestriction matches when:
       1. the effective product owner satisfies `ProductRestriction.owner`; and
       2. either `ProductRestriction.id` is absent, or the product has a `productId` matching the specified ID according to its `format`.
    3. If no restriction matches, return `INVALID`.
11. For each `document` in `ticket.transportDocument`:
    1. If `constraints.transportDocument` is absent, continue.
    2. For each document, perform 'Document Authorization Validation' with inputs `document` and `constraints.transportDocument`.
12. If no error occurred, return `SUCCESS`.

## Document Authorization Validation

Input: `document` of type `DocumentData`, `constraints` of type `DocumentConstraints`.

1. Select the `constraint` corresponding to the `DocumentData` choice:
   * `transportProduct`: `constraints.transportProduct`
   * `voucher`: `constraints.voucher`
   * `customerCard`: `constraints.customerCard`
   * `parkingGround`: `constraints.parking`
   * `stationPassage`: `constraints.stationPassage`
   * `delayConfirmation`: `constraints.delayConfirmation`
   * `token`: `constraints.token`
   * `extension`: `constraints.proprietary`
2. If the corresponding constraint is absent, return `INVALID`.
3. For `transportProduct`, perform 'Transport Product Authorization Validation'.
4. For `voucher`, perform 'Voucher Authorization Validation'.
5. For `delayConfirmation`, perform 'Delay Confirmation Authorization Validation'.
6. For `token`, perform 'Token Authorization Validation'.
7. For `customerCard`, `parkingGround` and `stationPassage`, if its `extension` is present:
   1. If `constraint.extension` is not set, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `extension`,
       `constraint.extension`, and the corresponding object set, returning any error.
8. For `extension`:
   1. If `constraint` is not set, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `extension`,
       `constraint`, and `ProprietaryDocumentTypes`, returning any error.
9. If no error occurred, return `SUCCESS`.

## Transport Product Authorization Validation

Input: `product` of type `TransportProduct`, `constraints` of type `TransportProductConstraints`.

1. Determine every effective ProductVariety applying to the transport product. For each:
   1. If it is ticket and `constraints.varietyTicket` is FALSE, return `INVALID`
   2. If it is reservation and `constraints.varietyReservation` is FALSE, return `INVALID`
   3. If it is commercialCard and `constraints.varietyCommercialCard` is FALSE, return `INVALID`
   4. If it is proprietary and `constraints.varietyProprietary is FALSE, return `INVALID`
2. If `constraints.permittedArea` is present, for every effective covered area, there **MUST** exist at least one entry which contains that entire covered area, otherwise return `INVALID`.
3. If `constraints.permittedNetwork` is present, verify every `coveredNetwork` is listed, otherwise return `INVALID`.
4. If `product.extension` is present:
   1. If `constraints.extension` is absent, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `product.extension`,
       `constraints.extension`, and `TransportProductExtensions`, returning any error.
5. For every applicable `Conditions.extension`:
   1. If `constraints.conditionsExtension` is absent, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `extension`,
       `constraints.conditionsExtension`, and `ConditionsExtensions`, returning any error.
6. If no error occurred, return `SUCCESS`.

## Voucher Authorization Validation

Input: `voucher` of type `Voucher`, `constraints` of type `VoucherConstraints`

1. If `constraints.currency` is present:
   1. Find an entry whose `currency` equals `issuingDetail.currency`.
   2. If no such entry exists, return `INVALID`.
   3. If that entry has `maximumValue`:
      1. Compare the monetary value represented by `voucher.value` and `issuingDetail.currencyFract`
          with the monetary value represented by `maximumValue.value` and `maximumValue.currencyFract`.
      2. If the voucher value is greater, return `INVALID`.
2. If `voucher.extension` is present:
   1. If `constraints.extension` is absent, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `voucher.extension`,
       `constraints.extension`, and `VoucherExtensions`, returning any error.
3. If no error occurred, return `SUCCESS`.

## Token Authorization Validation

Input: `token` of type `Token`, `constraints` of type `TokenConstraints`.

1. If `token.provider` is present, let `provider` be that value; otherwise let `provider`
    be the effective ticket issuer.
2. If `provider` does not satisfy `constraints.permittedProviders`, return `INVALID`.
3. If `constraints.permittedTokenTypes` is present:
   1. Perform the 'Data Authorization Validation' procedure with inputs `token.token`,
      `constraints.permittedTokenTypes`, and `TokenTypes`, returning any error.
4. If no error occurred, return `SUCCESS`.

## Delay Confirmation Authorization Validation

Input: `confirmation` of type `DelayConfirmation`, `constraints` of type `DelayConfirmationConstraints`.

1. If `confirmation.validityExtension` is present:
    1. If `transportLinkRemoved` is TRUE and `constraints.transportLinkRemoved` is FALSE, return `INVALID`.
    2. If `additionalTransportLink` is non-empty and `constraints.additionalTransportLink` is FALSE, return `INVALID`.
    3. If `additionalCarrier` is non-empty and `constraints.additionalCarrier` is FALSE, return `INVALID`.
       Every company in `additionalCarrier` **MUST** additionally satisfy the enclosing `MultiModalTicketConstraints.carriers`, if present.
    4. If `additionalServiceBrand` is non-empty and `constraints.additionalServiceBrand` is FALSE, return `INVALID`.
       Every service brand in `additionalServiceBrand` **MUST** additionally occur in the enclosing `MultiModalTicketConstraints.serviceBrands`, if present.
2. If `confirmation.extension` is present:
   1. If `constraints.extension` is absent, return `INVALID`.
   2. Otherwise, perform the 'Data Authorization Validation' procedure with inputs `confirmation.extension`,
       `constraints.extension`, and `DelayConfirmationExtensions`, returning any error.
3. If no error occurred, return `SUCCESS`.