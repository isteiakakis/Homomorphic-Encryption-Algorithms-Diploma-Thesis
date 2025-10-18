#include "he_linalg.h"
#include <cassert>

using namespace std;
using namespace seal;
using namespace he::operators;

namespace he::linalg
{
    Matrix::Matrix(size_t rows, size_t cols, const vector<Ciphertext> &elems)
        : dims {rows, cols}, elems(elems)
    {
    }

    Matrix::Matrix(size_t rows, size_t cols, vector<Ciphertext> &&elems)
        : dims {rows, cols}, elems(move(elems))
    {
    }

    Matrix::Matrix(size_t rows, size_t cols)
        : Matrix(rows, cols, vector<Ciphertext>(rows * cols))
    {
    }

    vector<size_t> Matrix::get_dims() const
    {
        return transposed ? vector<size_t>{dims[1], dims[0]} : dims;
    }

    bool Matrix::get_transp() const
    {
        return transposed;
    }

    void Matrix::transp()
    {
        transposed = !transposed;
    }

    const vector<Ciphertext> &Matrix::get_elems() const
    {
        return elems;
    }

    const Ciphertext &Matrix::operator()(bool colwise, size_t idx, bool dummy_arg) const
    {
        return elems[idx_to_idx(colwise, idx)];
    }

    Ciphertext &Matrix::operator()(bool colwise, size_t idx, bool dummy_arg)
    {
        return elems[idx_to_idx(colwise, idx)];
    }

    const Ciphertext &Matrix::operator()(size_t i, size_t j) const
    {
        return elems[ij_to_idx(i, j)];
    }

    Ciphertext &Matrix::operator()(size_t i, size_t j)
    {
        return elems[ij_to_idx(i, j)];
    }

    /*
     * Negate in-place
     */
    Matrix &Matrix::operator-=(const Evaluator &eval)
    {
        for (size_t idx = 0; idx < dims[0] * dims[1]; ++idx)
            elems[idx] -= eval;

        return *this;
    }

    /*
     * Negate
     */
    Matrix operator-(const tuple<const Evaluator &, const Matrix &> &eval_op)
    {
        Matrix res = get<1>(eval_op);
        return res -= get<0>(eval_op);
    }

    /*
     * Add in-place
     */
    Matrix &Matrix::operator+=(const tuple<const Evaluator &, const Matrix &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const Matrix &other = get<1>(eval_other);
        auto &thisr = *this;

        vector<size_t> op1_dims = get_dims();
        vector<size_t> op2_dims = other.get_dims();

        assert(op1_dims == op2_dims);

        for (size_t j = 0; j < op1_dims[1]; ++j)
            for (size_t i = 0; i < op1_dims[0]; ++i)
                thisr(i, j) += eval% other(i, j);

        return *this;
    }

    /*
     * Add
     */
    Matrix operator+(const tuple<const Evaluator &, const Matrix &> &eval_op1, const Matrix &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const Matrix &op1 = get<1>(eval_op1);

        Matrix res = op1;
        return res += eval% op2;
    }

    /*
     * Sub in-place
     */
    Matrix &Matrix::operator-=(const tuple<const Evaluator &, const Matrix &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const Matrix &other = get<1>(eval_other);
        auto &thisr = *this;

        vector<size_t> op1_dims = get_dims();
        vector<size_t> op2_dims = other.get_dims();

        assert(op1_dims == op2_dims);

        for (size_t j = 0; j < op1_dims[1]; ++j)
            for (size_t i = 0; i < op1_dims[0]; ++i)
                thisr(i, j) -= eval% other(i, j);

        return *this;
    }

    /*
     * Sub
     */
    Matrix operator-(const tuple<const Evaluator &, const Matrix &> &eval_op1, const Matrix &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const Matrix &op1 = get<1>(eval_op1);

        Matrix res = op1;
        return res -= eval% op2;
    }

    /*
     * Multiply in-place
     */
    Matrix &Matrix::operator*=(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const Matrix &> &eval_rk__other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__other));
        const RelinKeys &rk = get<1>(get<0>(eval_rk__other));
        const Matrix &other = get<1>(eval_rk__other);
        auto &thisr = *this;

        vector<size_t> op1_dims = get_dims();
        vector<size_t> op2_dims = other.get_dims();

        assert(op1_dims == op2_dims);

        for (size_t j = 0; j < op1_dims[1]; ++j)
            for (size_t i = 0; i < op1_dims[0]; ++i) {
                Ciphertext &res_ij = thisr(i, j);
                res_ij *= eval% other(i, j);

                res_ij &= eval% rk; // relin
                res_ij ^= eval; // rescale
            }

        return *this;
    }

    /*
     * Multiply
     */
    Matrix operator*(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const Matrix &> &eval_rk__op1, const Matrix &op2)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__op1));
        const RelinKeys & rk = get<1>(get<0>(eval_rk__op1));
        const Matrix &op1 = get<1>(eval_rk__op1);

        Matrix res = op1;
        return res *= eval% rk% op2;
    }

    /*
     * Matrix multiplication
     */
    Matrix Matrix::matmul(const Evaluator &eval, const RelinKeys &rk, const Matrix &other) const
    {
        using he::operators::operator%;
        using he::operators::operator*;

        vector<size_t> op1_dims = get_dims();
        vector<size_t> op2_dims = other.get_dims();

        assert(op1_dims[1] == op2_dims[0]);
        size_t inner_dim = op1_dims[1];

        Matrix res(op1_dims[0], op2_dims[1]);
        auto &thisr = *this;

        Ciphertext tmp_prod;

        for (size_t j = 0; j < res.dims[1]; ++j) {
            for (size_t i = 0; i < res.dims[0]; ++i) {
                Ciphertext &res_ij = res(i, j);
                size_t k = 0;
                {
                    res_ij = eval% thisr(i, k) * other(k, j);
                }
                for (++k; k < inner_dim; ++k) {
                    tmp_prod = eval% thisr(i, k) * other(k, j);
                    res_ij += eval% tmp_prod;
                }

                res_ij &= eval% rk; // relin
                res_ij ^= eval; // rescale
            }
        }

        return res;
    }

    /*
     * Left matrix multiplication with its transpose
     */
    Matrix Matrix::left_matmul_with_transp(const Evaluator &eval, const RelinKeys &rk) const
    {
        using he::operators::operator%;
        using he::operators::operator*;

        vector<size_t> op_dims = get_dims();

        size_t inner_dim = op_dims[0];

        Matrix res(op_dims[1], op_dims[1]);
        auto &thisr = *this;

        Ciphertext tmp_prod;

        for (size_t j = 0; j < res.dims[1]; ++j) {
            for (size_t i = 0; i < res.dims[0]; ++i) {
                Ciphertext &res_ij = res(i, j);
                size_t k = 0;
                {
                    res_ij = eval% thisr(k, i) * thisr(k, j);
                }
                for (++k; k < inner_dim; ++k) {
                    tmp_prod = eval% thisr(k, i) * thisr(k, j);
                    res_ij += eval% tmp_prod;
                }

                res_ij &= eval% rk; // relin
                res_ij ^= eval; // rescale
            }
        }

        return res;
    }

    /*
     * Matrix multiplication square
     */
    Matrix Matrix::matmul_square(const Evaluator &eval, const RelinKeys &rk) const
    {
        using he::operators::operator%;
        using he::operators::operator*;


        assert(dims[0] == dims[1]);

        const size_t d = dims[0]; // dimension

        Matrix res(dims[0], dims[1]);
        auto &thisr = *this;

        Ciphertext tmp_prod;

        for (size_t j = 0; j < res.dims[1]; ++j) {
            for (size_t i = 0; i < res.dims[0]; ++i) {
                Ciphertext &res_ij = res(i, j);
                size_t k = 0;
                {
                    res_ij = eval% thisr(i, k) * thisr(k, j);
                }
                for (++k; k < d; ++k) {
                    tmp_prod = eval% thisr(i, k) * thisr(k, j);
                    res_ij += eval% tmp_prod;
                }

                res_ij &= eval% rk; // relin
                res_ij ^= eval; // rescale
            }
        }

        return res;
    }

    /*
     * Matrix multiplication power
     */
    Matrix Matrix::matmul_pow(const Evaluator &eval, const RelinKeys &rk, int powr) const
    {
        assert(dims[0] == dims[1]); // Only square matrices

        const size_t d = dims[0]; // dimension
        Matrix res(d, d);
        Matrix tmp_prod = *this;

        int powr_binlen = ceil(log2(powr + 1));

        // R = A if n_bin[0] == '1' else np.eye(*A.shape)
        bool res_initd = false;
        if (powr & 1) {
            res = tmp_prod;
            res_initd = true;
        }

        for (size_t i = 1; i < powr_binlen; ++i) {
            // A = matsqr(A)
            tmp_prod = tmp_prod.matmul_square(eval, rk);
            if ((powr >> i) & 1) {
                if (!res_initd) {
                    // R = A
                    res = tmp_prod;
                    res_initd = true;
                } else {
                    // R = matmul(R, A)
                    res = res.matmul(eval, rk, tmp_prod);
                }
            }
        }

        return res;
    }

#if 0
    Matrix Matrix::solve_inplace(const CKKSEncoder &cencd, const Evaluator &eval, const RelinKeys &rk, const Matrix &b) const
    {
        // solve the system a * x = b
        // where a is a n*n matrix and b a n-vector

        // Number of equations
        size_t n = dims[0];

        auto &thisr = *this;

        // Dimension validation
        assert(n == dims[1]); // Only square matrices
        assert(n == b.get_dims()[0]); // b valid first dimension
        assert(b.get_dims()[1] == 1); // b is a vector

        Ciphertext driver_inv;

        for (size_t drc = 0; drc < n; ++drc) {
            driver_inv = he::math::inv_enhanced(cencd, eval, rk, thisr(drc, drc), 3);
            // TODO
        }
    }
#endif

    size_t Matrix::ij_to_idx(size_t i, size_t j) const
    {
        return (transposed ? j : i) + dims[0] * (transposed ? i : j);
    }

    size_t Matrix::idx_to_idx(bool colwise, size_t idx) const
    {
        return transposed != colwise ? idx : idx / dims[1] + idx % dims[1] * dims[0];
    }

    // -----------------------------------

    BatchedVector::BatchedVector(size_t dim, const Ciphertext &bvec)
        : dim(dim), bvec(bvec)
    {
    }

    BatchedVector::BatchedVector(size_t dim, Ciphertext &&bvec)
        : dim(dim), bvec(move(bvec))
    {
    }

    size_t BatchedVector::get_dim() const
    {
        return dim;
    }

    const Ciphertext &BatchedVector::get_bvec() const
    {
        return bvec;
    }

    /*
     * Negate in-place
     */
    BatchedVector &BatchedVector::operator-=(const Evaluator &eval)
    {
        bvec -= eval;
        return *this;
    }

    /*
     * Negate
     */
    BatchedVector operator-(const tuple<const Evaluator &, const BatchedVector &> &eval_op)
    {
        const Evaluator &eval = get<0>(eval_op);
        const BatchedVector &op = get<1>(eval_op);

        BatchedVector res = op;
        return res -= eval;
    }

    /*
     * Add in-place
     */
    BatchedVector &BatchedVector::operator+=(const tuple<const Evaluator &, const BatchedVector &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const BatchedVector &other = get<1>(eval_other);

        bvec += eval% other.bvec;
        return *this;
    }

    /*
     * Add
     */
    BatchedVector operator+(const tuple<const Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const BatchedVector &op1 = get<1>(eval_op1);

        BatchedVector res = op1;
        return res += eval% op2;
    }

    /*
     * Sub in-place
     */
    BatchedVector &BatchedVector::operator-=(const tuple<const Evaluator &, const BatchedVector &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const BatchedVector &other = get<1>(eval_other);

        bvec -= eval% other.bvec;
        return *this;
    }

    /*
     * Sub
     */
    BatchedVector operator-(const tuple<const Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const BatchedVector &op1 = get<1>(eval_op1);

        BatchedVector res = op1;
        return res -= eval% op2;
    }

    /*
     * Multiply in-place
     */
    BatchedVector &BatchedVector::operator*=(const tuple<const Evaluator &, const BatchedVector &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const BatchedVector &other = get<1>(eval_other);

        bvec *= eval% other.bvec;
        return *this;
    }

    /*
     * Multiply
     */
    BatchedVector operator*(const tuple<const Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const BatchedVector &op1 = get<1>(eval_op1);

        BatchedVector res = op1;
        return res *= eval% op2;
    }

    /*
     * Relinearize in-place
     */
    BatchedVector &BatchedVector::operator&=(const tuple<const Evaluator &, const RelinKeys &> &eval_rk)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_rk);
        const RelinKeys &rk = get<1>(eval_rk);

        bvec &= eval% rk;
        return *this;
    }

    /*
     * Relinearize
     */
    BatchedVector operator&(const tuple<const Evaluator &, const RelinKeys &> &eval_rk, const BatchedVector &op)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_rk);
        const RelinKeys &rk = get<1>(eval_rk);

        BatchedVector res = op;
        return res &= eval% rk;
    }

    /*
     * Rescale to next in-place
     */
    BatchedVector &BatchedVector::operator^=(const Evaluator &eval)
    {
        bvec ^= eval;
        return *this;
    }

    /*
     * Rescale to next
     */
    BatchedVector operator^(const Evaluator &eval, const BatchedVector &op)
    {
        BatchedVector res = op;
        return res ^= eval;
    }

    /*
     * Multiply in-place (relin and rescale)
     */
    BatchedVector &BatchedVector::operator*=(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const BatchedVector &> &eval_rk__other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__other));
        const RelinKeys &rk = get<1>(get<0>(eval_rk__other));
        const BatchedVector &other = get<1>(eval_rk__other);

        *this *= eval% other;
        *this &= eval% rk; // relin
        *this ^= eval; // rescale

        return *this;
    }

    /*
     * Multiply (relin and rescale)
     */
    BatchedVector operator*(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const BatchedVector &> &eval_rk__op1, const BatchedVector &op2)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__op1));
        const RelinKeys & rk = get<1>(get<0>(eval_rk__op1));
        const BatchedVector &op1 = get<1>(eval_rk__op1);

        BatchedVector res = op1;
        return res *= eval% rk% op2;
    }

    /*
     * Rotate left in-place
     */
    BatchedVector &BatchedVector::operator<<=(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const int &> &eval_gk__steps)
    {
        const Evaluator &eval = get<0>(get<0>(eval_gk__steps));
        const GaloisKeys &gk = get<1>(get<0>(eval_gk__steps));
        const int steps = get<1>(eval_gk__steps);

        eval.rotate_vector_inplace(bvec, steps, gk);
        return *this;
    }

    /*
     * Rotate left
     */
    BatchedVector operator<<(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const BatchedVector &> &eval_gk__op, int steps)
    {
        const Evaluator &eval = get<0>(get<0>(eval_gk__op));
        const GaloisKeys &gk = get<1>(get<0>(eval_gk__op));
        const BatchedVector &op = get<1>(eval_gk__op);

        BatchedVector res = op;
        eval.rotate_vector(op.bvec, steps, gk, res.bvec);
        return res;
    }

    /*
     * Rotate right in-place
     */
    BatchedVector &BatchedVector::operator>>=(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const int &> &eval_gk__steps)
    {
        const Evaluator &eval = get<0>(get<0>(eval_gk__steps));
        const GaloisKeys &gk = get<1>(get<0>(eval_gk__steps));
        const int steps = get<1>(eval_gk__steps);

        eval.rotate_vector_inplace(bvec, - steps, gk);
        return *this;
    }

    /*
     * Rotate right
     */
    BatchedVector operator>>(const tuple<const tuple<const Evaluator &, const GaloisKeys &> &, const BatchedVector &> &eval_gk__op, int steps)
    {
        const Evaluator &eval = get<0>(get<0>(eval_gk__op));
        const GaloisKeys &gk = get<1>(get<0>(eval_gk__op));
        const BatchedVector &op = get<1>(eval_gk__op);

        BatchedVector res = op;
        eval.rotate_vector(op.bvec, - steps, gk, res.bvec);
        return res;
    }

    /*
     * Square in-place
     */
    BatchedVector &BatchedVector::square_inplace(const Evaluator &eval, const RelinKeys &rk)
    {
        using he::operators::operator%;

        eval.square_inplace(bvec);
        bvec &= eval% rk; // relin
        bvec ^= eval; // rescale

        return *this;
    }

    /*
     * Square
     */
    BatchedVector BatchedVector::square(const Evaluator &eval, const RelinKeys &rk) const
    {
        BatchedVector res = *this;
        res.square_inplace(eval, rk);
        return res;
    }

    /*
     * Sum vector elements in-place
     */
    BatchedVector &BatchedVector::sum_elems_inplace(const Evaluator &eval, const GaloisKeys &gk)
    {
        using he::operators::operator%;
        using he::operators::operator+;
        using he::operators::operator<<;

        Ciphertext to_sum_ct = bvec;
        Ciphertext sum_ct;
        Ciphertext tmp_ct;
        int steps;
        int sum_window_size = 1;

        bool bvec_initd = false;
        if(dim & 1) {
            bvec_initd = true;
            to_sum_ct <<= eval% gk% sum_window_size;
        }

        for (size_t dim_bits = dim >> 1; dim_bits != 0; dim_bits >>= 1) {
            sum_window_size <<= 1;

            if (dim_bits & 1) {
                steps = sum_window_size >> 1;
                tmp_ct = eval% gk% to_sum_ct << steps;

                Ciphertext &sum_ct_ = bvec_initd ? sum_ct : bvec;
                sum_ct_ = eval% to_sum_ct + tmp_ct;

                for (steps >>= 1; steps != 0; steps >>= 1) {
                    tmp_ct = eval% gk% sum_ct_ << steps;
                    sum_ct_ += eval% tmp_ct;
                }

                if (bvec_initd)
                    bvec += eval% sum_ct;
                else
                    bvec_initd = true;

                if (dim_bits != 1)
                    to_sum_ct <<= eval% gk% sum_window_size;
            }
        }

        dim = 1;

        return *this;
    }

    /*
     * Sum vector elements in-place
     */
    BatchedVector BatchedVector::sum_elems(const Evaluator &eval, const GaloisKeys &gk)
    {
        BatchedVector res = *this;
        res.sum_elems_inplace(eval, gk);
        return res;
    }

    // -----------------------------------

    BatchedMatrix::BatchedMatrix(BatchingType btype, const vector<BatchedVector> &bvecs)
        : btype(btype), bvecs(bvecs)
    {
    }

    BatchedMatrix::BatchedMatrix(BatchingType btype, vector<BatchedVector> &&bvecs)
        : btype(btype), bvecs(move(bvecs))
    {
    }

    bool BatchedMatrix::get_transp() const
    {
        return transposed;
    }

    void BatchedMatrix::transp()
    {
        transposed = !transposed;
    }

    size_t BatchedMatrix::get_col_dim() const
    {
        return !transposed ? bvecs.size() : bvecs[0].get_dim();
    }

    size_t BatchedMatrix::get_row_dim() const
    {
        return transposed ? bvecs.size() : bvecs[0].get_dim();
    }

    const vector<BatchedVector> &BatchedMatrix::get_bvecs() const
    {
        return bvecs;
    }

    /*
     * Return the i-th bvec
     */
    const BatchedVector &BatchedMatrix::operator[](size_t i) const
    {
        return bvecs[i];
    }

    /*
     * Return the i-th bvec
     */
    BatchedVector &BatchedMatrix::operator[](size_t i)
    {
        return bvecs[i];
    }

    /*
     * Negate in-place
     */
    BatchedMatrix &BatchedMatrix::operator-=(const Evaluator &eval)
    {
        for (auto &bvec : bvecs) {
            bvec -= eval;
        }

        return *this;
    }

    /*
     * Negate
     */
    BatchedMatrix operator-(const tuple<const Evaluator &, const BatchedMatrix &> &eval_op)
    {
        const Evaluator &eval = get<0>(eval_op);
        const BatchedMatrix &op = get<1>(eval_op);

        BatchedMatrix res = op;
        return res -= eval;
    }

    /*
     * Add in-place
     */
    BatchedMatrix &BatchedMatrix::operator+=(const tuple<const Evaluator &, const BatchedMatrix &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const BatchedMatrix &other = get<1>(eval_other);

        assert(transposed == other.transposed);

        for (size_t i = 0; i < bvecs.size(); ++i)
            bvecs[i] += eval% other.bvecs[i];

        return *this;
    }

    /*
     * Add
     */
    BatchedMatrix operator+(const tuple<const Evaluator &, const BatchedMatrix &> &eval_op1, const BatchedMatrix &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const BatchedMatrix &op1 = get<1>(eval_op1);

        BatchedMatrix res = op1;
        return res += eval% op2;
    }

    /*
     * Sub in-place
     */
    BatchedMatrix &BatchedMatrix::operator-=(const tuple<const Evaluator &, const BatchedMatrix &> &eval_other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(eval_other);
        const BatchedMatrix &other = get<1>(eval_other);

        assert(transposed == other.transposed);

        for (size_t i = 0; i < bvecs.size(); ++i)
            bvecs[i] -= eval% other.bvecs[i];

        return *this;
    }

    /*
     * Sub
     */
    BatchedMatrix operator-(const tuple<const Evaluator &, const BatchedMatrix &> &eval_op1, const BatchedMatrix &op2)
    {
        const Evaluator &eval = get<0>(eval_op1);
        const BatchedMatrix &op1 = get<1>(eval_op1);

        BatchedMatrix res = op1;
        return res -= eval% op2;
    }

    /*
     * Multiply in-place
     */
    BatchedMatrix &BatchedMatrix::operator*=(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const BatchedMatrix &> &eval_rk__other)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__other));
        const RelinKeys &rk = get<1>(get<0>(eval_rk__other));
        const BatchedMatrix &other = get<1>(eval_rk__other);

        assert(transposed == other.transposed);

        for (size_t i = 0; i < bvecs.size(); ++i)
            bvecs[i] *= eval% rk% other.bvecs[i];

        return *this;
    }

    /*
     * Multiply
     */
    BatchedMatrix operator*(const tuple<const tuple<const Evaluator &, const RelinKeys &> &, const BatchedMatrix &> &eval_rk__op1, const BatchedMatrix &op2)
    {
        using he::operators::operator%;

        const Evaluator &eval = get<0>(get<0>(eval_rk__op1));
        const RelinKeys & rk = get<1>(get<0>(eval_rk__op1));
        const BatchedMatrix &op1 = get<1>(eval_rk__op1);

        BatchedMatrix res = op1;
        return res *= eval% rk% op2;
    }

    /*
     * Square in-place
     */
    BatchedMatrix &BatchedMatrix::square_inplace(const Evaluator &eval, const RelinKeys &rk)
    {
        using he::operators::operator%;

        for (auto &bvec : bvecs)
            bvec.square_inplace(eval, rk);

        return *this;
    }

    /*
     * Square
     */
    BatchedMatrix BatchedMatrix::square(const Evaluator &eval, const RelinKeys &rk) const
    {
        BatchedMatrix res = *this;
        res.square_inplace(eval, rk);
        return res;
    }

    /*
     * Sum vector elements in-place
     */
    BatchedMatrix &BatchedMatrix::sum_bvec_elems_inplace(const Evaluator &eval, const GaloisKeys &gk)
    {
        for (auto &bvec : bvecs)
            bvec.sum_elems_inplace(eval, gk);

        return *this;
    }

    /*
     * Sum vector elements in-place
     */
    BatchedMatrix BatchedMatrix::sum_bvec_elems(const Evaluator &eval, const GaloisKeys &gk)
    {
        BatchedMatrix res = *this;
        res.sum_bvec_elems_inplace(eval, gk);
        return res;
    }

    /*
     * Matrix multiplication
     */
    BatchedMatrix BatchedMatrix::matmul(const Evaluator &eval, const RelinKeys &rk, const GaloisKeys &gk, const BatchedMatrix &other) const
    {
        using he::operators::operator%;

        assert(other.btype == BatchingType::col);
        assert(!transposed);

        auto &thisr = *this;

        size_t m = get_row_dim();
        size_t n = get_col_dim();
        size_t p = other.get_col_dim();

        vector<BatchedVector> res_bmat_v;
        res_bmat_v.reserve(m);

        BatchingType res_btype;

        bool btype_is_col = btype == BatchingType::col;

        if (btype_is_col) {
            assert(other.transposed);
            assert(n == other.get_row_dim());

            res_btype = BatchingType::diag;

        } else {
            assert(!other.transposed);

            res_btype = BatchingType::col;
        }

#define SMART_RELIN 1

        for (size_t i = 0; i < p; ++i) { // for each result batched vector
            {
                res_bmat_v.emplace_back(eval% gk% other[btype_is_col ? 0 : i] << (btype_is_col ? i : 0));
                res_bmat_v[i] *= eval% thisr[0];

#if SMART_RELIN == 0
                res_bmat_v[i] &= eval% rk;
                res_bmat_v[i] ^= eval;
#endif
            }
            for (size_t j = 1; j < n; ++j) { // sum the products
                BatchedVector tmp_bvec = eval% gk% other[btype_is_col ? j : i] << (btype_is_col ? i : j);
                tmp_bvec *= eval% thisr[j];

#if SMART_RELIN == 0
                tmp_bvec &= eval% rk; // relin
                tmp_bvec ^= eval; // rescale
#endif

                res_bmat_v[i] += eval% tmp_bvec;
            }

#if SMART_RELIN == 1
            res_bmat_v[i] &= eval% rk; // relin
            res_bmat_v[i] ^= eval; // rescale
#endif
        }

        return BatchedMatrix(res_btype, move(res_bmat_v));
    }
} // namespace he::linalg
