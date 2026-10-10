#include "crypto/zero_knowledge_proof/schnorr.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef FIREBLOCKS_SCHNORR_REPLAY
#include <array>
#include <cstdio>
#endif

// Corpus format: 32-byte prover ID | 33-byte compressed public point |
// 33-byte proof.R | 32-byte proof.s. Extra bytes are ignored so mutations
// which append data still exercise the verifier.
namespace {
constexpr std::size_t kIdLength = 32;
constexpr std::size_t kPointLength = ELLIPTIC_CURVE_COMPRESSED_POINT_LEN;
constexpr std::size_t kScalarLength = ELLIPTIC_CURVE_FIELD_SIZE;
constexpr std::size_t kInputLength =
    kIdLength + kPointLength + kPointLength + kScalarLength;

static_assert(kPointLength == 33, "unexpected point encoding");
static_assert(kScalarLength == 32, "unexpected scalar encoding");
static_assert(sizeof(schnorr_zkp_t) == kPointLength + kScalarLength,
              "unexpected Schnorr proof layout");

struct ScopedAlgebra {
    elliptic_curve256_algebra_ctx_t *ctx =
        elliptic_curve256_new_secp256k1_algebra();

    ~ScopedAlgebra() { elliptic_curve256_algebra_ctx_free(ctx); }

    ScopedAlgebra(const ScopedAlgebra &) = delete;
    ScopedAlgebra &operator=(const ScopedAlgebra &) = delete;
    ScopedAlgebra() = default;
};

zero_knowledge_proof_status verify_one(const std::uint8_t *data,
                                       std::size_t size) {
    if (data == nullptr || size < kInputLength) {
        return ZKP_INVALID_PARAMETER;
    }

    ScopedAlgebra algebra;
    if (algebra.ctx == nullptr) {
        return ZKP_OUT_OF_MEMORY;
    }

    elliptic_curve256_point_t public_data{};
    schnorr_zkp_t proof{};
    std::memcpy(public_data, data + kIdLength, kPointLength);
    std::memcpy(proof.R, data + kIdLength + kPointLength, kPointLength);
    std::memcpy(proof.s, data + kIdLength + 2 * kPointLength, kScalarLength);

    return schnorr_zkp_verify(algebra.ctx, data, kIdLength, &public_data,
                              &proof);
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
    (void)verify_one(data, size);
    return 0;
}

#ifdef FIREBLOCKS_SCHNORR_REPLAY
// Build with -DFIREBLOCKS_SCHNORR_REPLAY to confirm corpus seeds against the
// pinned libcosigner; a valid proof exits 0, other verifier results exit 1.
int main(int argc, char **argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s INPUT_FILE\n", argv[0]);
        return 2;
    }
    std::FILE *file = std::fopen(argv[1], "rb");
    if (file == nullptr) {
        return 2;
    }
    std::array<std::uint8_t, kInputLength> input{};
    const std::size_t read = std::fread(input.data(), 1, input.size(), file);
    const int trailing = std::fgetc(file);
    std::fclose(file);
    if (read != input.size() || trailing != EOF) {
        std::fprintf(stderr, "expected exactly %zu bytes\n", input.size());
        return 2;
    }
    const auto status = verify_one(input.data(), input.size());
    std::printf("verify status: %d\n", static_cast<int>(status));
    return status == ZKP_SUCCESS ? 0 : 1;
}
#endif
