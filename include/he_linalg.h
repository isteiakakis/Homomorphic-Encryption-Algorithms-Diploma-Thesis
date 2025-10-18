#pragma once

#include "he_operators.h"
#include "seal/seal.h"
#include <vector>

namespace he::linalg
{
    class Matrix;
    class BatchedVector;
    class BatchedMatrix;

    template <typename T>
    concept Matrix_BatchedVector_BatchedMatrix_tn = std::same_as<std::decay_t<T>, Matrix> ||
                                      std::same_as<std::decay_t<T>, BatchedVector> ||
                                      std::same_as<std::decay_t<T>, BatchedMatrix>;

    /**
     * Tie two things together using %
     */
    template<Matrix_BatchedVector_BatchedMatrix_tn T>
    constexpr auto operator%(const seal::Evaluator &eval, T &&op)
    {
        return std::tie(eval, std::forward<T>(op));
    }

    /**
     * Tie three things together using %
     */
    template<Matrix_BatchedVector_BatchedMatrix_tn T>
    constexpr auto operator%(const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &eval_rk, T &&op)
    {
        return std::tie(eval_rk, std::forward<T>(op));
    }

    /**
     * Tie three things together using %
     */
    template<Matrix_BatchedVector_BatchedMatrix_tn T>
    constexpr auto operator%(const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &eval_gk, T &&op)
    {
        return std::tie(eval_gk, std::forward<T>(op));
    }

    // -----------------------------------

    class Matrix
    {
    public:
        Matrix() = delete;
        Matrix(const Matrix &copy) = default;
        Matrix(Matrix &&source) = default;
        ~Matrix() = default;
        Matrix &operator=(const Matrix &copy) = default;
        Matrix &operator=(Matrix &&source) = default;

        Matrix(std::size_t rows, std::size_t cols, const std::vector<seal::Ciphertext> &elems);

        Matrix(std::size_t rows, std::size_t cols, std::vector<seal::Ciphertext> &&elems);

        Matrix(std::size_t rows, std::size_t cols);

        std::vector<std::size_t> get_dims() const;

        void transp();

        bool get_transp() const;

        const std::vector<seal::Ciphertext> &get_elems() const;

        const seal::Ciphertext &operator()(bool colwise, std::size_t idx, bool dummy_arg) const;

        seal::Ciphertext &operator()(bool colwise, std::size_t idx, bool dummy_arg);

        const seal::Ciphertext &operator()(std::size_t i, std::size_t j) const;

        seal::Ciphertext &operator()(std::size_t i, std::size_t j);

        void set_elem(std::size_t i, std::size_t j, const seal::Ciphertext &elem);

        void set_elem(std::size_t i, std::size_t j, seal::Ciphertext &&elem);

        /**
         * Negate in-place
         */
        Matrix &operator-=(const seal::Evaluator &eval);

        /**
         * Negate
         */
        friend Matrix operator-(const std::tuple<const seal::Evaluator &, const Matrix &> &eval_op);

        /**
         * Add in-place
         */
        Matrix &operator+=(const std::tuple<const seal::Evaluator &, const Matrix &> &eval_other);

        /**
         * Add
         */
        friend Matrix operator+(const std::tuple<const seal::Evaluator &, const Matrix &> &eval_op1, const Matrix &op2);

        /**
         * Sub in-place
         */
        Matrix &operator-=(const std::tuple<const seal::Evaluator &, const Matrix &> &eval_other);

        /**
         * Sub
         */
        friend Matrix operator-(const std::tuple<const seal::Evaluator &, const Matrix &> &eval_op1, const Matrix &op2);

        /**
         * Multiply in-place
         */
        Matrix &operator*=(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const Matrix &> &eval_rk__other);

        /**
         * Multiply
         */
        friend Matrix operator*(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const Matrix &> &eval_rk__op1, const Matrix &op2);

        /**
         * Square in-place
         */
        //TODO
        //Matrix square_inplace(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Square
         */
        //TODO
        //Matrix square(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Power
         */
        //TODO
        //Matrix pow(const seal::Evaluator &eval, const seal::RelinKeys &rk, int powr) const;

        /**
         * Matrix multiplication
         */
        Matrix matmul(const seal::Evaluator &eval, const seal::RelinKeys &rk, const Matrix &other) const;

        /**
         * Left matrix multiplication with its transpose
         */
        Matrix left_matmul_with_transp(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Matrix multiplication square
         */
        Matrix matmul_square(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Matrix multiplication power
         */
        Matrix matmul_pow(const seal::Evaluator &eval, const seal::RelinKeys &rk, int powr) const;

    private:
        std::size_t ij_to_idx(std::size_t i, std::size_t j) const;
        std::size_t idx_to_idx(bool colwise, std::size_t idx) const;

        std::vector<std::size_t> dims;
        bool transposed = false;
        std::vector<seal::Ciphertext> elems {};
    };

    // -----------------------------------

    class BatchedVector
    {
    public:
        BatchedVector() = delete;
        BatchedVector(const BatchedVector &copy) = default;
        BatchedVector(BatchedVector &&source) = default;
        ~BatchedVector() = default;
        BatchedVector &operator=(const BatchedVector &copy) = default;
        BatchedVector &operator=(BatchedVector &&source) = default;

        BatchedVector(std::size_t dim, const seal::Ciphertext &bvec);

        BatchedVector(std::size_t dim, seal::Ciphertext &&bvec);

        std::size_t get_dim() const;

        const seal::Ciphertext &get_bvec() const;

        /**
         * Negate in-place
         */
        BatchedVector &operator-=(const seal::Evaluator &eval);

        /**
         * Negate
         */
        friend BatchedVector operator-(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_op);

        /**
         * Add in-place
         */
        BatchedVector &operator+=(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_other);

        /**
         * Add
         */
        friend BatchedVector operator+(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2);

        /**
         * Sub in-place
         */
        BatchedVector &operator-=(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_other);

        /**
         * Sub
         */
        friend BatchedVector operator-(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2);

        /**
         * Multiply in-place
         */
        BatchedVector &operator*=(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_other);

        /**
         * Multiply
         */
        friend BatchedVector operator*(const std::tuple<const seal::Evaluator &, const BatchedVector &> &eval_op1, const BatchedVector &op2);

        /**
         * Relinearize in-place
         */
        BatchedVector &operator&=(const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &eval_rk);

        /**
         * Relinearize
         */
        friend BatchedVector operator&(const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &eval_rk, const BatchedVector &op);

        /**
         * Rescale to next in-place
         */
        BatchedVector &operator^=(const seal::Evaluator &eval);

        /**
         * Rescale to next
         */
        friend BatchedVector operator^(const seal::Evaluator &eval, const BatchedVector &op);

        /**
         * Multiply in-place (relin and rescale)
         */
        BatchedVector &operator*=(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const BatchedVector &> &eval_rk__other);

        /**
         * Multiply (relin and rescale)
         */
        friend BatchedVector operator*(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const BatchedVector &> &eval_rk__op1, const BatchedVector &op2);

        /**
         * Rotate left in-place
         */
        BatchedVector &operator<<=(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const int &> &eval_gk__steps);

        /**
         * Rotate left
         */
        friend BatchedVector operator<<(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const BatchedVector &> &eval_gk__op, int steps);

        /**
         * Rotate right in-place
         */
        BatchedVector &operator>>=(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const int &> &eval_gk__steps);

        /**
         * Rotate right
         */
        friend BatchedVector operator>>(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::GaloisKeys &> &, const BatchedVector &> &eval_gk__op, int steps);

        /**
         * Square in-place
         */
        BatchedVector &square_inplace(const seal::Evaluator &eval, const seal::RelinKeys &rk);

        /**
         * Square
         */
        BatchedVector square(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Sum vector elements in-place
         */
        BatchedVector &sum_elems_inplace(const seal::Evaluator &eval, const seal::GaloisKeys &gk);

        /**
         * Sum vector elements in-place
         */
        BatchedVector sum_elems(const seal::Evaluator &eval, const seal::GaloisKeys &gk);

    private:
        std::size_t dim;
        seal::Ciphertext bvec;
    };

    // -----------------------------------

    class BatchedMatrix
    {
    public:
        BatchedMatrix() = delete;
        BatchedMatrix(const BatchedMatrix &copy) = default;
        BatchedMatrix(BatchedMatrix &&source) = default;
        ~BatchedMatrix() = default;

        BatchedMatrix &operator=(const BatchedMatrix &copy) = default;
        BatchedMatrix &operator=(BatchedMatrix &&source) = default;

        enum class BatchingType { col, diag };

        BatchedMatrix(BatchingType btype, const std::vector<BatchedVector> &bvecs);
        BatchedMatrix(BatchingType btype, std::vector<BatchedVector> &&bvecs);

        BatchingType get_btype() const;

        std::size_t get_col_dim() const;
        std::size_t get_row_dim() const;

        bool get_transp() const;
        void transp();

        const std::vector<BatchedVector> &get_bvecs() const;

        /**
         * Return the i-th bvec
         */
        const BatchedVector &operator[](size_t i) const;

        /**
         * Return the i-th bvec
         */
        BatchedVector &operator[](size_t i);

        /**
         * Negate in-place
         */
        BatchedMatrix &operator-=(const seal::Evaluator &eval);

        /**
         * Negate
         */
        friend BatchedMatrix operator-(const std::tuple<const seal::Evaluator &, const BatchedMatrix &> &eval_op);

        /**
         * Add in-place
         */
        BatchedMatrix &operator+=(const std::tuple<const seal::Evaluator &, const BatchedMatrix &> &eval_other);

        /**
         * Add
         */
        friend BatchedMatrix operator+(const std::tuple<const seal::Evaluator &, const BatchedMatrix &> &eval_op1, const BatchedMatrix &op2);

        /**
         * Sub in-place
         */
        BatchedMatrix &operator-=(const std::tuple<const seal::Evaluator &, const BatchedMatrix &> &eval_other);

        /**
         * Sub
         */
        friend BatchedMatrix operator-(const std::tuple<const seal::Evaluator &, const BatchedMatrix &> &eval_op1, const BatchedMatrix &op2);

        /**
         * Multiply in-place
         */
        BatchedMatrix &operator*=(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const BatchedMatrix &> &eval_rk__other);

        /**
         * Multiply
         */
        friend BatchedMatrix operator*(const std::tuple<const std::tuple<const seal::Evaluator &, const seal::RelinKeys &> &, const BatchedMatrix &> &eval_rk__op1, const BatchedMatrix &op2);

        /**
         * Square in-place
         */
        BatchedMatrix &square_inplace(const seal::Evaluator &eval, const seal::RelinKeys &rk);

        /**
         * Square
         */
        BatchedMatrix square(const seal::Evaluator &eval, const seal::RelinKeys &rk) const;

        /**
         * Sum vector elements in-place
         */
        BatchedMatrix &sum_bvec_elems_inplace(const seal::Evaluator &eval, const seal::GaloisKeys &gk);

        /**
         * Sum vector elements in-place
         */
        BatchedMatrix sum_bvec_elems(const seal::Evaluator &eval, const seal::GaloisKeys &gk);

        /**
         * Matrix multiplication
         */
        BatchedMatrix matmul(const seal::Evaluator &eval, const seal::RelinKeys &rk, const seal::GaloisKeys &gk, const BatchedMatrix &other) const;

    private:
        BatchingType btype;
        bool transposed = false;
        std::vector<BatchedVector> bvecs;
    };
} // namespace he::linalg
