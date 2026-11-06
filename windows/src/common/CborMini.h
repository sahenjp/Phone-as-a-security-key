// CborMini.h - the smallest possible CBOR reader, just enough to find
// the authData byte string (key 2) inside an authenticatorMakeCredential
// response produced by our Rust core, so the credential ID can be
// extracted for platform metadata sync.
//
// This is NOT a general CBOR library: it only walks definite- and
// indefinite-length items with bounds checks, and every failure simply
// aborts the (best-effort) sync. All multi-byte integers are big-endian
// per RFC 8949.

#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <span>

namespace pfk::cbor {

class Reader {
public:
    explicit Reader(std::span<const BYTE> data) : m_data(data) {}

    bool Empty() const { return m_pos >= m_data.size(); }

    // Read one item header: major type (0-7) and argument. For major 7
    // the argument is the simple/float value encoding; float payloads
    // are consumed by SkipValue via the additional-info size.
    bool ReadHeader(uint8_t& major, uint64_t& arg, uint8_t& addInfo) {
        if (m_pos >= m_data.size()) {
            return false;
        }
        const BYTE first = m_data[m_pos++];
        major = static_cast<uint8_t>(first >> 5);
        addInfo = static_cast<uint8_t>(first & 0x1F);
        if (addInfo < 24) {
            arg = addInfo;
            return true;
        }
        if (addInfo == 24) {
            if (m_pos + 1 > m_data.size()) return false;
            arg = m_data[m_pos++];
            return true;
        }
        if (addInfo == 25) {
            if (m_pos + 2 > m_data.size()) return false;
            arg = (static_cast<uint64_t>(m_data[m_pos]) << 8) | m_data[m_pos + 1];
            m_pos += 2;
            return true;
        }
        if (addInfo == 26) {
            if (m_pos + 4 > m_data.size()) return false;
            arg = 0;
            for (int i = 0; i < 4; ++i) arg = (arg << 8) | m_data[m_pos++];
            return true;
        }
        if (addInfo == 27) {
            if (m_pos + 8 > m_data.size()) return false;
            arg = 0;
            for (int i = 0; i < 8; ++i) arg = (arg << 8) | m_data[m_pos++];
            return true;
        }
        // 28-30 are reserved; 31 means indefinite length, reported via
        // arg = kIndefinite so callers can loop until a break stop code.
        if (addInfo == 31) {
            arg = kIndefinite;
            return true;
        }
        return false;
    }

    static constexpr uint64_t kIndefinite = ~uint64_t{0};

    // If the next item is a signed/unsigned integer, return its value
    // (negative integers are returned as -1 - arg, matching CBOR).
    bool ReadInt(int64_t& value) {
        const size_t save = m_pos;
        uint8_t major = 0, addInfo = 0;
        uint64_t arg = 0;
        if (!ReadHeader(major, arg, addInfo)) {
            m_pos = save;
            return false;
        }
        if (major == 0) {
            value = static_cast<int64_t>(arg);
            return true;
        }
        if (major == 1) {
            value = -1 - static_cast<int64_t>(arg);
            return true;
        }
        m_pos = save;
        return false;
    }

    // If the next item is a byte string, return its contents.
    bool ReadByteString(std::span<const BYTE>& out) {
        const size_t save = m_pos;
        uint8_t major = 0, addInfo = 0;
        uint64_t arg = 0;
        if (!ReadHeader(major, arg, addInfo) || major != 2) {
            m_pos = save;
            return false;
        }
        if (arg == kIndefinite) {
            // Our encoder never emits indefinite byte strings; refuse
            // rather than stitch chunks (sync is best-effort).
            m_pos = save;
            return false;
        }
        if (m_pos + arg > m_data.size()) {
            m_pos = save;
            return false;
        }
        out = m_data.subspan(m_pos, static_cast<size_t>(arg));
        m_pos += static_cast<size_t>(arg);
        return true;
    }

    // Skip one complete item (recursively for containers).
    bool SkipValue() {
        uint8_t major = 0, addInfo = 0;
        uint64_t arg = 0;
        if (!ReadHeader(major, arg, addInfo)) {
            return false;
        }
        return SkipBody(major, arg, addInfo);
    }

private:
    bool SkipBody(uint8_t major, uint64_t arg, uint8_t addInfo) {
        switch (major) {
            case 0:  // unsigned int - header already holds the value
            case 1:  // negative int
                return true;
            case 7:  // simple / float - payload was consumed by ReadHeader
                return true;
            case 6:  // tag - one following item
                return SkipValue();
            case 2:  // byte string
            case 3:  // text string
                if (arg == kIndefinite) {
                    // Chunks until break stop code (0xFF).
                    for (;;) {
                        if (m_pos < m_data.size() && m_data[m_pos] == 0xFF) {
                            ++m_pos;
                            return true;
                        }
                        if (!SkipValue()) return false;
                    }
                }
                if (m_pos + arg > m_data.size()) return false;
                m_pos += static_cast<size_t>(arg);
                return true;
            case 4:  // array
                if (arg == kIndefinite) {
                    for (;;) {
                        if (m_pos < m_data.size() && m_data[m_pos] == 0xFF) {
                            ++m_pos;
                            return true;
                        }
                        if (!SkipValue()) return false;
                    }
                }
                for (uint64_t i = 0; i < arg; ++i) {
                    if (!SkipValue()) return false;
                }
                return true;
            case 5:  // map
                if (arg == kIndefinite) {
                    for (;;) {
                        if (m_pos < m_data.size() && m_data[m_pos] == 0xFF) {
                            ++m_pos;
                            return true;
                        }
                        if (!SkipValue() || !SkipValue()) return false;
                    }
                }
                for (uint64_t i = 0; i < arg; ++i) {
                    if (!SkipValue() || !SkipValue()) return false;
                }
                return true;
            default:
                return false;
        }
    }

    std::span<const BYTE> m_data;
    size_t m_pos = 0;
};

// Find the byte string stored under integer key `wantedKey` in the
// top-level map. Returns false if absent or malformed.
inline bool FindMapByteString(std::span<const BYTE> cborData, int64_t wantedKey,
                              std::span<const BYTE>& out) {
    Reader reader(cborData);
    uint8_t major = 0, addInfo = 0;
    uint64_t pairs = 0;
    if (!reader.ReadHeader(major, pairs, addInfo) || major != 5) {
        return false;
    }
    const bool indefinite = (pairs == Reader::kIndefinite);
    for (uint64_t i = 0; indefinite || i < pairs; ++i) {
        if (indefinite && reader.Empty()) {
            return false;
        }
        int64_t key = 0;
        if (!reader.ReadInt(key)) {
            return false;
        }
        if (key == wantedKey) {
            return reader.ReadByteString(out);
        }
        if (!reader.SkipValue()) {
            return false;
        }
    }
    return false;
}

// Extract the credential ID from authenticator data:
//   rpIdHash(32) | flags(1) | signCount(4) |
//   [ AAGUID(16) | credIdLen(2, BE) | credentialId ]   (when flags & AT)
inline bool ExtractCredentialId(std::span<const BYTE> authData,
                                std::span<const BYTE>& credentialId) {
    constexpr size_t kFixedPart = 32 + 1 + 4;
    if (authData.size() < kFixedPart) {
        return false;
    }
    const BYTE flags = authData[32];
    if ((flags & 0x40) == 0) {  // AT flag: attested credential data present
        return false;
    }
    constexpr size_t kCredLenOffset = kFixedPart + 16;
    if (authData.size() < kCredLenOffset + 2) {
        return false;
    }
    const size_t credIdLen =
        (static_cast<size_t>(authData[kCredLenOffset]) << 8) |
        static_cast<size_t>(authData[kCredLenOffset + 1]);
    const size_t credIdOffset = kCredLenOffset + 2;
    if (credIdLen == 0 || authData.size() < credIdOffset + credIdLen) {
        return false;
    }
    credentialId = authData.subspan(credIdOffset, credIdLen);
    return true;
}

}  // namespace pfk::cbor
