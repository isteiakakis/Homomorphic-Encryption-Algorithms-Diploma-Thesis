#include "he_operators.h"
#include "seal/seal.h"
#include <tuple>
#include <utility>

using namespace std;
using namespace seal;

namespace he::operators
{
    /*
     * Negate in-place
     */
    Ciphertext &operator-=(Ciphertext &op, const Evaluator &eval)
    {
        eval.negate_inplace(op);
        return op;
    }

    /*
     * Negate
     */
    Ciphertext operator-(const tuple<const Evaluator &, const Ciphertext &> &eval_ct)
    {
        Ciphertext res;
        get<0>(eval_ct).negate(get<1>(eval_ct), res);
        return res;
    }

    /*
     * Add in-place
     */
    Ciphertext &operator+=(Ciphertext &op1, const tuple<const Evaluator &, const Ciphertext &> &eval_op2)
    {
        get<0>(eval_op2).add_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Add
     */
    Ciphertext operator+(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Ciphertext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).add(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Add plain in-place
     */
    Ciphertext &operator+=(Ciphertext &op1, const tuple<const Evaluator &, const Plaintext &> &eval_op2)
    {
        get<0>(eval_op2).add_plain_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Add plain
     */
    Ciphertext operator+(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Plaintext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).add_plain(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Sub in-place
     */
    Ciphertext &operator-=(Ciphertext &op1, const tuple<const Evaluator &, const Ciphertext &> &eval_op2)
    {
        get<0>(eval_op2).sub_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Sub
     */
    Ciphertext operator-(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Ciphertext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).sub(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Sub plain in-place
     */
    Ciphertext &operator-=(Ciphertext &op1, const tuple<const Evaluator &, const Plaintext &> &eval_op2)
    {
        get<0>(eval_op2).sub_plain_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Sub plain
     */
    Ciphertext operator-(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Plaintext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).sub_plain(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Multiply in-place
     */
    Ciphertext &operator*=(Ciphertext &op1, const tuple<const Evaluator &, const Ciphertext &> &eval_op2)
    {
        get<0>(eval_op2).multiply_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Multiply
     */
    Ciphertext operator*(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Ciphertext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).multiply(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Multiply plain in-place
     */
    Ciphertext &operator*=(Ciphertext &op1, const tuple<const Evaluator &, const Plaintext &> &eval_op2)
    {
        get<0>(eval_op2).multiply_plain_inplace(op1, get<1>(eval_op2));
        return op1;
    }

    /*
     * Multiply plain
     */
    Ciphertext operator*(const tuple<const Evaluator &, const Ciphertext &> &eval_op1, const Plaintext &op2)
    {
        Ciphertext res;
        get<0>(eval_op1).multiply_plain(get<1>(eval_op1), op2, res);
        return res;
    }

    /*
     * Relinearize in-place
     */
    Ciphertext &operator&=(Ciphertext &op, const tuple<const Evaluator &, const RelinKeys &> &eval_rk)
    {
        get<0>(eval_rk).relinearize_inplace(op, get<1>(eval_rk));
        return op;
    }

    /*
     * Relinearize
     */
    Ciphertext operator&(const tuple<const Evaluator &, const RelinKeys &> &eval_rk, const Ciphertext &op)
    {
        Ciphertext res;
        get<0>(eval_rk).relinearize(op, get<1>(eval_rk), res);
        return res;
    }

    /*
     * Rescale to next in-place
     */
    Ciphertext &operator^=(Ciphertext &op, const Evaluator &eval)
    {
        eval.rescale_to_next_inplace(op);
        return op;
    }

    /*
     * Rescale to next
     */
    Ciphertext operator^(const Evaluator &eval, const Ciphertext &op)
    {
        Ciphertext res;
        eval.rescale_to_next(op, res);
        return res;
    }

    /*
     * Mod switch to next in-place
     */
    Ciphertext &operator|=(Ciphertext &op, const Evaluator &eval)
    {
        eval.mod_switch_to_next_inplace(op);
        return op;
    }

    /*
     * Mod switch to next
     */
    Ciphertext operator|(const Evaluator &eval, const Ciphertext &op)
    {
        Ciphertext res;
        eval.mod_switch_to_next(op, res);
        return res;
    }

    /*
     * CKKS rotate left in-place
     */
    Ciphertext &operator<<=(Ciphertext &op, const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const int &> &eval_gk__steps)
    {
        get<0>(get<0>(eval_gk__steps)).rotate_vector_inplace(op, get<1>(eval_gk__steps), get<1>(get<0>(eval_gk__steps)));
        return op;
    }

    /*
     * CKKS rotate left
     */
    Ciphertext operator<<(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const Ciphertext &> &eval_gk__op, int steps)
    {
        Ciphertext res;
        get<0>(get<0>(eval_gk__op)).rotate_vector(get<1>(eval_gk__op), steps, get<1>(get<0>(eval_gk__op)), res);
        return res;
    }

    /*
     * CKKS rotate right in-place
     */
    Ciphertext &operator>>=(Ciphertext &op, const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const int &> &eval_gk__steps)
    {
        get<0>(get<0>(eval_gk__steps)).rotate_vector_inplace(op, - get<1>(eval_gk__steps), get<1>(get<0>(eval_gk__steps)));
        return op;
    }

    /*
     * CKKS rotate right
     */
    Ciphertext operator>>(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const Ciphertext &> &eval_gk__op, int steps)
    {
        Ciphertext res;
        get<0>(get<0>(eval_gk__op)).rotate_vector(get<1>(eval_gk__op), - steps, get<1>(get<0>(eval_gk__op)), res);
        return res;
    }
} // namespace he::operators
