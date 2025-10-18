#include "he_math.h"
#include "he_operators.h"
#include "he_util.h"
#include "seal/seal.h"
#include <cassert>
#include <cmath>

using namespace std;
using namespace seal;
using namespace he::operators;

namespace he::math
{
    // TODO NOW
    // create a function `reach_chain_level`
    // develop: (unsigned) `inv`, `sign`, `max`, `div`, ...
    //     about `div`: a flavor of `inv` that includes a numerator instead of a dummy multiplication with one before the for loop

    /*
     * f(x) = 1/x
     */
    Ciphertext signed_inv(const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Ciphertext &x_ct, double a, size_t iter_num)
    {
        assert(iter_num > 0);

        Ciphertext y_ct; // result

        // Compute the first product term
        {
            // Encode -a^2
            Plaintext minus_a_squared_pt;
            cencd.encode(-a*a, x_ct.parms_id(), x_ct.scale(), minus_a_squared_pt);

            // - a^2 * x
            y_ct = eval% x_ct * minus_a_squared_pt;
            y_ct ^= eval; // rescale

            // Encode 2*a
            Plaintext a2_pt;
            cencd.encode(2*a, y_ct.parms_id(), y_ct.scale(), a2_pt);

            // (2 * a) + (- a^2 * x)
            y_ct += eval% a2_pt;
        }

        if (iter_num == 1)
            return y_ct;

        Ciphertext a_x_minus_1_ct; // the a*x-1 term used in the following product terms

        // Encode a
        Plaintext a_pt;
        cencd.encode(a, x_ct.parms_id(), x_ct.scale(), a_pt);

        // a * x
        a_x_minus_1_ct = eval% x_ct * a_pt;
        a_x_minus_1_ct ^= eval; // rescale

        // Encode 1
        Plaintext one_pt;
        cencd.encode(1, a_x_minus_1_ct.parms_id(), a_x_minus_1_ct.scale(), one_pt);

        // (a * x) - 1
        a_x_minus_1_ct -= eval% one_pt;

        // Drop y one level for parameter match with the following product term
        y_ct *= eval% one_pt;
        y_ct ^= eval; // rescale

        // Compute the rest of the product
        Ciphertext prod_term_ct;

        for (int i = 1; i < iter_num; ++i) {
            // (a * x - 1)^2
            eval.square_inplace(a_x_minus_1_ct);
            a_x_minus_1_ct &= eval% rk; // relin
            a_x_minus_1_ct ^= eval; // rescale

            // (a * x - 1)^2 + 1
            cencd.encode(1, a_x_minus_1_ct.parms_id(), a_x_minus_1_ct.scale(), one_pt);
            prod_term_ct = eval% a_x_minus_1_ct + one_pt;

            // product
            y_ct *= eval% prod_term_ct;
            y_ct &= eval% rk; // relin
            y_ct ^= eval; // rescale
        }

        return y_ct;
    }

    /*
     * f(x) = 1/sqrt(2x)
     */
    Ciphertext inv_sqrt_twice(const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Ciphertext &x_ct, double a, size_t iter_num)
    {
        assert(iter_num > 0);

        Ciphertext x_ct_ = x_ct; // input
        double y_prev = a; // init value
        Ciphertext y_ct; // result

        // Perform the first iteration
        {
            // - y_prev^3
            Plaintext minus_y_prev_cubd_pt;
            cencd.encode(- y_prev * y_prev * y_prev, x_ct_.parms_id(), x_ct_.scale(), minus_y_prev_cubd_pt);

            // x * (- y_prev^3)
            y_ct = eval% x_ct_ * minus_y_prev_cubd_pt;
            y_ct ^= eval; // rescale

            // 3/2 * y_prev
            Plaintext threehalves_y_prev_pt;
            cencd.encode(3.0/2 * y_prev, y_ct.parms_id(), y_ct.scale(), threehalves_y_prev_pt);

            // (- x * y_prev^3) + (3/2 * y_prev)
            y_ct += eval% threehalves_y_prev_pt;
        }

        Plaintext number_pt;
        Ciphertext x_y_prev_ct;
        Ciphertext y_prev_ct;

#if 1
        // Less multiplicative depth (depth 2 per loop)
        for (size_t i = 1; i < iter_num; ++i) {
            y_prev_ct = y_ct;

            // 3/2 * y_prev
            cencd.encode(3.0/2, y_ct.parms_id(), y_ct.scale(), number_pt);
            y_ct *= eval% number_pt;
            y_ct ^= eval; // rescale

            // Rescale once more for parameter matching in the following operations
            cencd.encode(1, y_ct.parms_id(), y_ct.scale(), number_pt);
            y_ct *= eval% number_pt;
            y_ct ^= eval; // rescale

            // Rescale x to reach y_prev
            for (size_t j = 0; j < (i > 1 ? 2 : 1); ++j) {
                cencd.encode(1, x_ct_.parms_id(), x_ct_.scale(), number_pt);
                x_ct_ *= eval% number_pt;
                x_ct_ ^= eval; // rescale
            }

            // x * y_prev
            x_y_prev_ct = eval% x_ct_ * y_prev_ct;
            x_y_prev_ct &= eval% rk; // relin
            x_y_prev_ct ^= eval; // rescale

            // y_prev^2
            eval.square_inplace(y_prev_ct);
            y_prev_ct &= eval% rk; // relin
            y_prev_ct ^= eval; // rescale

            // (x * y_prev) * (y_prev^2)
            y_prev_ct *= eval% x_y_prev_ct;
            y_prev_ct &= eval% rk; // relin
            y_prev_ct ^= eval; // rescale

            // (3/2 * y_prev) - (x * y_prev^3)
            y_ct -= eval% y_prev_ct;
        }
#else
        // Runs a little bit faster (depth 3 per loop)
        for (size_t i = 1; i < iter_num; ++i) {
            y_prev_ct = y_ct;

            // Rescale x to reach y_prev^2
            for (size_t j = 0; j < (i > 1 ? 3 : 2); ++j) {
                cencd.encode(1, x_ct_.parms_id(), x_ct_.scale(), number_pt);
                x_ct_ *= eval% number_pt;
                x_ct_ ^= eval; // rescale
            }

            // y_prev^2
            eval.square(y_prev_ct, y_ct);
            y_ct &= eval% rk; // relin
            y_ct ^= eval; // rescale

            // x * (y_prev^2)
            y_ct *= eval% x_ct_;
            y_ct &= eval% rk; // relin
            y_ct ^= eval; // rescale

            // 3/2 - (x * y_prev^2)
            cencd.encode(3.0/2, y_ct.parms_id(), y_ct.scale(), number_pt);
            y_ct -= eval% number_pt;
            y_ct -= eval;

            // Rescale y_prev to reach 3/2 - (x * y_prev^2)
            for (size_t i = 0; i < 2; ++i) {
                cencd.encode(1, y_prev_ct.parms_id(), y_prev_ct.scale(), number_pt);
                y_prev_ct *= eval% number_pt;
                y_prev_ct ^= eval; // rescale
            }

            // (3/2 - x * y_prev^2) * y_prev
            y_ct *= eval% y_prev_ct;
            y_ct &= eval% rk; // relin
            y_ct ^= eval; // rescale
        }
#endif
        return y_ct;
    }

    /*
     * f(x) = sqrt(x)
     */
    Ciphertext sqrt(const SEALContext &ctx, const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Ciphertext &x_ct, double a, size_t iter_num)
    {
        // 1/sqrt(2*x)
        Ciphertext y_ct = inv_sqrt_twice(cencd, eval, rk, x_ct, 1/a/std::sqrt(2), iter_num);

        // sqrt(2) * x
        Plaintext number_pt;
        cencd.encode(std::sqrt(2), x_ct.parms_id(), x_ct.scale(), number_pt);
        Ciphertext sqrt2_x_ct;
        sqrt2_x_ct = eval% x_ct * number_pt;
        sqrt2_x_ct ^= eval; // rescale

        // Rescale (sqrt(2) * x) to reach (1/sqrt(2*x))
        he::util::reach_chain_level(ctx, cencd, eval, number_pt, sqrt2_x_ct, y_ct);

        // (1/sqrt(2*x)) * (sqrt(2) * x)
        y_ct *= eval% sqrt2_x_ct;
        y_ct &= eval% rk; // relin
        y_ct ^= eval; // rescale

        return y_ct;
    }

    /*
     * f(x) = |x|
     */
    Ciphertext abs(const SEALContext &ctx, const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Ciphertext &x_ct, double a, size_t iter_num)
    {
        // x^2
        Ciphertext x_sqrd_ct;
        eval.square(x_ct, x_sqrd_ct);
        x_sqrd_ct &= eval% rk; // relin
        x_sqrd_ct ^= eval; // rescale

        // 1/sqrt(2*x^2) = 1/(sqrt(2)*|x|)
        Ciphertext y_ct = inv_sqrt_twice(cencd, eval, rk, x_sqrd_ct, 1/a/std::sqrt(2), iter_num);

        // sqrt(2) * x^2
        Plaintext sqrt_two_pt;
        cencd.encode(std::sqrt(2), x_sqrd_ct.parms_id(), x_sqrd_ct.scale(), sqrt_two_pt);
        x_sqrd_ct *= eval% sqrt_two_pt;
        x_sqrd_ct ^= eval; // rescale

        // Rescale (sqrt(2) * x^2) to reach (1/(sqrt(2)*|x|))
        Plaintext one_pt;
        size_t num_of_rescales = ctx.get_context_data(x_sqrd_ct.parms_id())->chain_index() - ctx.get_context_data(y_ct.parms_id())->chain_index();
        for (size_t i = 0; i < num_of_rescales; ++i) {
            cencd.encode(1, x_sqrd_ct.parms_id(), x_sqrd_ct.scale(), one_pt);
            x_sqrd_ct *= eval% one_pt;
            x_sqrd_ct ^= eval; // rescale
        }

        // (1/(sqrt(2)*|x|)) * (sqrt(2) * x^2)
        y_ct *= eval% x_sqrd_ct;
        y_ct &= eval% rk; // relin
        y_ct ^= eval; // rescale

        return y_ct;
    }

    /*
     * f(x1, x2) = (min|max)(x1, x2)
     */
    template<int min_or_max>
    static Ciphertext minmax(const SEALContext &ctx, const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Ciphertext &x_ct, double a, size_t iter_num)
    {
        // TODO
        Ciphertext y_ct;
        return y_ct;
    }

} // namespace he::math
