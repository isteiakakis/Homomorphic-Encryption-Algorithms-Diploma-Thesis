#pragma once

#include "he_operators.h"
#include "seal/seal.h"

namespace he::math
{
    /**
     * Evaluate f(x) = 1/x, x real or complex, x != 0
     *
     * `a` is a prediction of the result.
     * For real numbers, `a` must have the same sign with x; more specifically, 0 < a*x < 2 must hold.
     * More generaly, for complex numbers, |a*x - 1| < 1 must hold.
     */
    seal::Ciphertext signed_inv(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::RelinKeys &rk, const seal::Ciphertext &x_ct, double a, std::size_t iter_num);

    /**
     * Evaluate f(x) = 1/sqrt(2x), x real, x > 0
     *
     * `a` is a prediction of the result.
     * 0 < a < sqrt(3/(2x)) must hold.
     */
    seal::Ciphertext inv_sqrt_twice(const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::RelinKeys &rk, const seal::Ciphertext &x_ct, double a, size_t iter_num);

    /**
     * f(x) = sqrt(x)
     */
    seal::Ciphertext sqrt(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::RelinKeys &rk, const seal::Ciphertext &x_ct, double a, size_t iter_num);

    /**
     * f(x) = |x|
     */
    seal::Ciphertext abs(const seal::SEALContext &ctx, const seal::CKKSEncoder &cencd, const seal::Evaluator &eval, const seal::RelinKeys &rk, const seal::Ciphertext &x_ct, double a, size_t iter_num);
} // namespace he::math
