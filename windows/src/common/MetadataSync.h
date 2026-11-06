// MetadataSync.h - best-effort sync of credential metadata to the
// platform (WebAuthNPluginAuthenticatorAddCredentials), mirroring what
// the sample does after MakeCredential via its local credential DB
// (PluginCredentialManager::AddPluginCredentialById).
//
// The difference: the sample has a local vault DB to read metadata from.
// Our credentials live on the phone, and the fixed Rust C ABI has no
// list-credentials call, so the only metadata available on the PC is
// what one ceremony carries: RP/user from the decoded request, and the
// credential ID from inside the response's authData. That is enough for
// the "just created" entry. Deletions and credentials created on other
// PCs cannot be reconciled from here - see the ABI-gap note in
// windows/README.md.
//
// Everything here is fire-and-forget: a sync failure must never fail the
// ceremony itself.

#pragma once

#include <windows.h>

#include <span>

namespace pfk {

// After a successful MakeCredential pfk_process() call: decode the
// request, extract the new credential ID from the response, and publish
// the metadata. `request` is the raw platform request (command byte +
// CBOR), `response` is the raw pfk_process() output (status byte +
// CBOR). Returns true if metadata was published.
bool SyncNewCredential(std::span<const BYTE> request,
                       std::span<const BYTE> response);

}  // namespace pfk
