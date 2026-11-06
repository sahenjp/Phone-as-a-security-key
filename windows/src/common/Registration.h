// Registration.h - platform registration of the plugin authenticator.
//
// Reduced from the sample's PluginManagement/PluginRegistrationManager:
// the sample hand-assembles its authenticatorGetInfo CBOR from hex
// fragments; we take the Rust core's GetInfo response
// (pfk_static_get_info()) and strip its leading CTAP status byte,
// which yields the same bare authenticator-info map the Linux daemon
// serves. Everything else - AddAuthenticator, storing the operation
// signing public key under HKCU, RemoveAuthenticator, GetAuthenticatorState -
// follows the sample.

#pragma once

#include <windows.h>
#include <webauthn/webauthnplugin.h>

namespace pfk {

// Register the authenticator with the platform
// (WebAuthNPluginAddAuthenticator) and store the returned operation
// signing public key in the registry for reference, like the sample.
// Returns NTE_NOT_FOUND-flavoured errors from the platform unchanged.
HRESULT RegisterPlugin();

// Remove the authenticator registration
// (WebAuthNPluginRemoveAuthenticator). Credential metadata is removed
// first (best effort) so no orphaned entries stay in the platform's
// autofill database.
HRESULT UnregisterPlugin();

// Current platform state of our authenticator. On success `registered`
// tells whether WebAuthNPluginGetAuthenticatorState knew our CLSID at
// all, and `state` (when registered) is AuthenticatorState_Enabled /
// AuthenticatorState_Disabled - the user flips it in
// Settings > Accounts > Passkeys, we cannot.
HRESULT QueryPluginState(bool& registered, AUTHENTICATOR_STATE& state);

}  // namespace pfk
