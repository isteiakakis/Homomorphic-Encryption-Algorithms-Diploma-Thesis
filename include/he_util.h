#pragma once

#include "seal/seal.h"
#include <string>

namespace he::util
{
    inline std::string uint64_to_hex_string(uint64_t value)
    {
        return seal::util::uint_to_hex_string(&value, 1);
    }

    inline std::size_t get_chain_index(const seal::SEALContext &ctx, const seal::Ciphertext &ct)
    {
        return ctx.get_context_data(ct.parms_id())->chain_index();
    }

    inline std::size_t get_chain_index(const seal::EncryptionParameters &parms, const seal::Ciphertext &ct)
    {
        return get_chain_index(seal::SEALContext(parms), ct);
    }

    template <typename T>
    concept vectorCiphertextPtr_tn = std::same_as<std::decay_t<T>, seal::Ciphertext> ||
                                     std::same_as<std::decay_t<T>, std::vector<seal::Ciphertext *>>;

    template <vectorCiphertextPtr_tn T>
    inline void drop_chain_levels(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, seal::Plaintext &one_pt, T &&res_ct, size_t num_of_levels)
    {
        for (size_t _ = 0; _ < num_of_levels; ++_) {
            if constexpr (std::is_same<std::decay_t<T>, seal::Ciphertext>::value)
            {
                cencd.encode(1, res_ct.parms_id(), res_ct.scale(), one_pt);

                eval.multiply_plain_inplace(res_ct, one_pt);
                eval.rescale_to_next_inplace(res_ct);
            }
            else
            {
                cencd.encode(1, res_ct[0]->parms_id(), res_ct[0]->scale(), one_pt);

                for (auto r : res_ct) {
                    eval.multiply_plain_inplace(*r, one_pt);
                    eval.rescale_to_next_inplace(*r);
                }
            }
        }
    }

    template <vectorCiphertextPtr_tn T>
    inline void drop_chain_levels(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, T &&res_ct, size_t num_of_levels)
    {
        seal::Plaintext one_pt;
        drop_chain_levels(ctx, cencd, eval, one_pt, std::forward<T>(res_ct), num_of_levels);
    }

    template <vectorCiphertextPtr_tn T>
    inline void reach_chain_level(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, seal::Plaintext &one_pt, T &&res_ct, const seal::Ciphertext &to_reach_ct)
    {
        size_t num_of_levels;

        if constexpr (std::is_same<std::decay_t<T>, seal::Ciphertext>::value)
            num_of_levels = get_chain_index(ctx, res_ct);
        else
            num_of_levels = get_chain_index(ctx, *res_ct[0]);

        num_of_levels -= get_chain_index(ctx, to_reach_ct);

        drop_chain_levels(ctx, cencd, eval, one_pt, std::forward<T>(res_ct), num_of_levels);
    }

    template <vectorCiphertextPtr_tn T>
    inline void reach_chain_level(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, T &&res_ct, const seal::Ciphertext &to_reach_ct)
    {
        seal::Plaintext one_pt;
        reach_chain_level(ctx, cencd, eval, one_pt, std::forward<T>(res_ct), to_reach_ct);
    }
} // namespace he::util
