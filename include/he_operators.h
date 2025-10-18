#pragma once

#include "seal/seal.h"
#include <tuple>
#include <utility>

/* Operator overlading of basic HE functions */

// TODO: make everything constexpr

namespace he::operators
{
    template <typename T>
    concept Plaintext_Ciphertext_GaloisKeys_RelinKeys_tn = std::same_as<std::decay_t<T>, seal::Plaintext> ||
                                                           std::same_as<std::decay_t<T>, seal::Ciphertext> ||
                                                           std::same_as<std::decay_t<T>, seal::GaloisKeys> ||
                                                           std::same_as<std::decay_t<T>, seal::RelinKeys>;

    /**
     * Tie two things together using %
     */
    template<Plaintext_Ciphertext_GaloisKeys_RelinKeys_tn T>
    constexpr auto operator%(const seal::Evaluator &eval, T &&op)
    {
        return std::tie(eval, std::forward<T>(op));
    }

    template<typename T>
    concept Ciphertext_int_tn = std::same_as<std::decay_t<T>, seal::Ciphertext> ||
                                     std::same_as<std::decay_t<T>, int>;

    /**
     * Tie three things together using %
     */
    template<Ciphertext_int_tn T>
    constexpr auto operator%(const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &eval_gk, T &&op)
    {
        return std::tie(eval_gk, std::forward<T>(op));
    }

    /**
     * Negate in-place
     */
    seal::Ciphertext &operator-=(seal::Ciphertext &op, const seal::Evaluator &eval);

    /**
     * Negate
     */
    seal::Ciphertext operator-(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op);

    /**
     * Add in-place
     */
    seal::Ciphertext &operator+=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op2);

    /**
     * Add
     */
    seal::Ciphertext operator+(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Ciphertext &op2);

    /**
     * Add plain in-place
     */
    seal::Ciphertext &operator+=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Plaintext &> &eval_op2);

    /**
     * Add plain
     */
    seal::Ciphertext operator+(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Plaintext &op2);

    /**
     * Sub in-place
     */
    seal::Ciphertext &operator-=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op2);

    /**
     * Sub
     */
    seal::Ciphertext operator-(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Ciphertext &op2);

    /**
     * Sub plain in-place
     */
    seal::Ciphertext &operator-=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Plaintext &> &eval_op2);

    /**
     * Sub plain
     */
    seal::Ciphertext operator-(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Plaintext &op2);

    /**
     * Multiply in-place
     */
    seal::Ciphertext &operator*=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op2);

    /**
     * Multiply
     */
    seal::Ciphertext operator*(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Ciphertext &op2);

    /**
     * Multiply plain in-place
     */
    seal::Ciphertext &operator*=(seal::Ciphertext &op1, const std::tuple<const seal::Evaluator &, const seal::Plaintext &> &eval_op2);

    /**
     * Multiply plain
     */
    seal::Ciphertext operator*(const std::tuple<const seal::Evaluator &, const seal::Ciphertext &> &eval_op1, const seal::Plaintext &op2);

    /**
     * Relinearize in-place
     */
    seal::Ciphertext &operator&=(seal::Ciphertext &op, const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &eval_rk);

    /**
     * Relinearize
     */
    seal::Ciphertext operator&(const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &eval_rk, const seal::Ciphertext &op);

    /**
     * Rescale to next in-place
     */
    seal::Ciphertext &operator^=(seal::Ciphertext &op, const seal::Evaluator &eval);

    /**
     * Rescale to next
     */
    seal::Ciphertext operator^(const seal::Evaluator &eval, const seal::Ciphertext &op);

    /**
     * Mod switch to next in-place
     */
    seal::Ciphertext &operator|=(seal::Ciphertext &op, const seal::Evaluator &eval);

    /**
     * Mod switch to next
     */
    seal::Ciphertext operator|(const seal::Evaluator &eval, const seal::Ciphertext &op);

    /**
     * CKKS rotate left in-place
     */
    seal::Ciphertext &operator<<=(seal::Ciphertext &op, const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const int &> &eval_gk__steps);

    /**
     * CKKS rotate left
     */
    seal::Ciphertext operator<<(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const seal::Ciphertext &> &eval_gk__op, int steps);

    /**
     * CKKS rotate right in-place
     */
    seal::Ciphertext &operator>>=(seal::Ciphertext &op, const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const int &> &eval_gk__steps);

    /**
     * CKKS rotate right
     */
    seal::Ciphertext operator>>(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const seal::Ciphertext &> &eval_gk__op, int steps);
} // namespace he::operators
