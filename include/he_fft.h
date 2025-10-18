#pragma once

#include "seal/seal.h"
#include <complex>
#include <vector>

namespace he::fft
{
    /**
     * Run FFT on a vector of ciphertexts
     */
    std::vector<seal::Ciphertext> fft(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const std::vector<seal::Ciphertext> &vec_ct);

    /**
     * Run IFFT on a vector of ciphertexts
     */
    std::vector<seal::Ciphertext> ifft(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const std::vector<seal::Ciphertext> &vec_ct);

    /**
     * Run FFT on the batched elements inside a single ciphertext (Batched FFT)
     */
    seal::Ciphertext bfft(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::GaloisKeys &gk, const seal::Ciphertext &x_ct, std::size_t n);

    /**
     * Run IFFT on the batched elements inside a single ciphertext (Batched FFT)
     */
    seal::Ciphertext ibfft(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::GaloisKeys &gk, const seal::Ciphertext &x_ct, std::size_t n);
} // namespace he::fft
