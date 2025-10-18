#include "he_linalg.h"
#include "he_math.h"
#include "he_util.h"
#include "tic_toc.h"
#include <cassert>

using namespace std;
using namespace seal;
using namespace he::operators;
using namespace he::linalg;
using Complex = complex<double>;

namespace
{
    template<typename T>
    vector<vector<T>> perform_matmul(
            const size_t slot_no,
            const vector<size_t> &mat1_dims,
            const vector<size_t> &mat2_dims,
            const vector<vector<T>> &mat1,
            const vector<vector<T>> &mat2)
    {
        if (mat1_dims[1] != mat2_dims[0]) {
            cout << "!!! Matrix dimension mismatch !!!" << '\n';
            return {};
        }

        size_t inner_dim = mat1_dims[1];

        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);
        vector<vector<T>> mat3(slot_no, vector<T>(mat3_elem_no));

        for (size_t s = 0; s < slot_no; ++s) {
            for (size_t i = 0; i < mat3_dims[0]; ++i) {
                for (size_t j = 0; j < mat3_dims[1]; ++j) {
                    T &mat3_cur_el = mat3[s][ mat3_dims[1] * i + j ];
                    size_t k = 0;
                    {
                        const T &mat1_cur_el = mat1[s][ mat1_dims[1] * i + k ];
                        const T &mat2_cur_el = mat2[s][ mat2_dims[1] * k + j ];
                        mat3_cur_el = mat1_cur_el * mat2_cur_el;
                    }
                    for (++k; k < inner_dim; ++k) {
                        const T &mat1_cur_el = mat1[s][ mat1_dims[1] * i + k ];
                        const T &mat2_cur_el = mat2[s][ mat2_dims[1] * k + j ];
                        T tmp;
                        tmp = mat1_cur_el * mat2_cur_el;
                        mat3_cur_el += tmp;
                    }
                }
            }
        }

        return mat3;
    }

    void bench_he_op()
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        double scale = pow(2.0, 40);
        SEALContext ctx(parms);

        /*
         * Set up keys, encryptor, decryptor, CKKS encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data
         */
        Complex mat1(2, 5), mat2(-5, 1);

        /*
         * Set up plaintexts
         */
        Plaintext mat1_pt, mat2_pt;
        cencd.encode({mat1}, scale, mat1_pt);
        cencd.encode({mat2}, scale, mat2_pt);

        /*
         * Encrypt
         */
        Ciphertext mat1_ct, mat2_ct;
        enc.encrypt(mat1_pt, mat1_ct);
        enc.encrypt(mat2_pt, mat2_ct);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
                }
                );

        /*
         * Perform encrypted operation
         */
        Ciphertext mat3_ct;
        mat3_ct = eval% mat1_ct * mat2_ct;
        mat3_ct &= eval% rk; // relinearize
        mat3_ct ^= eval; // rescale

        /*
         * Decrypt result
         */
        Plaintext mat3_pt;
        vector<Complex> mat3_;
        Complex mat3;
        dec.decrypt(mat3_ct, mat3_pt);
        cencd.decode(mat3_pt, mat3_);
        mat3 = mat3_[0];

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        cout << mat3 << ' ';
        cout << '\n';
        cout << ']' << "\n\n";
    }

    void bench_he_elemwise_square()
    {
        /*
         * Set up the encryption parameters (enabling batching) and create context
         */
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        int plain_modulus_bit_no = 30;
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plain_modulus_bit_no));
        SEALContext ctx(parms);
        //cout << "Parameter validation: " << ctx.parameter_error_message() << '\n';
        //print_parameters(ctx); cout << '\n';
        //cout << "Batching enabled: " << ctx.first_context_data()->qualifiers().using_batching << '\n';

        /*
         * Set up keys, encryptor, decryptor, batch encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        BatchEncoder bencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data
         */
        size_t slot_no = bencd.slot_count();
        vector<uint64_t> data(slot_no);
        for (size_t i = 0; i < slot_no; ++i) {
            data[i] = i;
        }
        //print_matrix(data, slot_no/2);

        /*
         * Set up plaintext
         */
        Plaintext pt;
        bencd.encode(data, pt);

        /*
         * Encrypt
         */
        Ciphertext ct;
        enc.encrypt(pt, ct);

        /*
         * Perform an operation
         */
        cout << "Noise budget: " << dec.invariant_noise_budget(ct) << '\n';
        eval.square_inplace(ct);
        cout << "Noise budget: " << dec.invariant_noise_budget(ct) << '\n';
        eval.relinearize_inplace(ct, rk);
        cout << "Noise budget: " << dec.invariant_noise_budget(ct) << '\n';

        /*
         * Decrypt result
         */
        dec.decrypt(ct, pt);
        bencd.decode(pt, data);

        //print_matrix(data, slot_no/2);

    }

    void bench_he_matmul()
    {
        /*
         * Set up the encryption parameters (enabling batching) and create context
         */
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        int plain_modulus_bit_no = 20;
        parms.set_plain_modulus(1 << plain_modulus_bit_no);
        SEALContext ctx(parms);
        //cout << "Parameter validation: " << ctx.parameter_error_message() << '\n';
        //print_parameters(ctx); cout << '\n';
        //cout << "Batching enabled: " << ctx.first_context_data()->qualifiers().using_batching << '\n';

        /*
         * Set up keys, encryptor, decryptor, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        Evaluator eval(ctx);

        /*
         * Set up data (the two matrices to be multiplied)
         */
        vector<size_t> mat1_dims({2, 2}), mat2_dims({2, 2});
        size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
        size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);
        vector<uint64_t> mat1(mat1_elem_no);
        vector<uint64_t> mat2(mat2_elem_no);
        for (size_t i = 0; i < mat1.size(); ++i)
            mat1[i] = i + 1;
        for (size_t i = 0; i < mat2.size(); ++i)
            mat2[i] = i + 5;

        /*
         * Print operand matrices
         */
        //cout << "Print operand matrices:" << '\n';
        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat1_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat1_dims[1]; ++j) {
        //        cout << mat1[ mat1_dims[1] * i + j ] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat2_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat2_dims[1]; ++j) {
        //        cout << mat2[ mat2_dims[1] * i + j ] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        /*
         * Set up plaintexts
         */
        vector<Plaintext> mat1_pt(mat1_elem_no);
        vector<Plaintext> mat2_pt(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            mat1_pt[i] = Plaintext(he::util::uint64_to_hex_string(mat1[i]));
        for (size_t i = 0; i < mat2_elem_no; ++i)
            mat2_pt[i] = Plaintext(he::util::uint64_to_hex_string(mat2[i]));

        /*
         * Encrypt
         */
        vector<Ciphertext> mat1_ct(mat1_elem_no);
        vector<Ciphertext> mat2_ct(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            enc.encrypt(mat1_pt[i], mat1_ct[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            enc.encrypt(mat2_pt[i], mat2_ct[i]);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
                }
                );

        /*
         * Perform encrypted matrix multiplication
         */
        Timer t;
        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);

        t.tic();
        //vector<Ciphertext> mat3_ct = perform_he_matmul(eval, rk, mat1_dims, mat2_dims, mat1_ct, mat2_ct);
        Matrix m1(mat1_dims[0], mat1_dims[1], mat1_ct);
        Matrix m2(mat2_dims[0], mat2_dims[1], mat2_ct);

        //Matrix m3 = m1.mul(eval, rk, m2);
        m1.transp();
        Matrix m3 = m1.matmul_pow(eval, rk, 5);

        t.toc("HE (no batch) matrix multiplication time");

        /*
         * Decrypt result
         */
        vector<Plaintext> mat3_pt(mat3_elem_no);
        for (size_t i = 0; i < mat3_elem_no; ++i) {
            dec.decrypt(m3(false, i, false), mat3_pt[i]);
        }

        /*
         * Print result
         */
        cout << "Noise budget: " << dec.invariant_noise_budget(m3(false, 0, false)) << '\n';
        stringstream ss;
        uint64_t rslt;
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < mat3_dims[0]; ++i) {
            for (size_t j = 0; j < mat3_dims[1]; ++j) {
                ss.str(mat3_pt[ mat3_dims[1] * i + j ].to_string());
                ss >> hex >> rslt;
                ss.clear();
                cout << rslt << ' ';
            }
            cout << '\n';
        }
        cout << ']' << "\n\n";

    }

    void bench_he_batch_matmul_bfv()
    {
        /*
         * Set up the encryption parameters (enabling batching) and create context
         */
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        int plain_modulus_bit_no = 60;
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plain_modulus_bit_no));
        SEALContext ctx(parms);
        //cout << "Parameter validation: " << ctx.parameter_error_message() << '\n';
        //print_parameters(ctx); cout << '\n';
        //cout << "Batching enabled: " << ctx.first_context_data()->qualifiers().using_batching << '\n';

        /*
         * Set up keys, encryptor, decryptor, batch encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        BatchEncoder bencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data (a lot of pairs of matrices to be multiplied in parallel)
         */
        size_t slot_no = bencd.slot_count();
        vector<size_t> mat1_dims({5, 5}), mat2_dims({5, 5});
        size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
        size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);
        vector<vector<uint64_t>> mat1(mat1_elem_no, vector<uint64_t>(slot_no));
        vector<vector<uint64_t>> mat2(mat2_elem_no, vector<uint64_t>(slot_no));
        for (size_t s = 0; s < slot_no; ++s) {
            for (size_t i = 0; i < mat1.size(); ++i)
                mat1[i][s] = i + s + 7;
            for (size_t i = 0; i < mat2.size(); ++i)
                mat2[i][s] = i + s + 9;
        }

        /*
         * Print operand matrices
         */
        size_t slot_to_print = 8000;
        //cout << "Print operand matrices:" << '\n';
        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat1_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat1_dims[1]; ++j) {
        //        cout << mat1[ mat1_dims[1] * i + j ][slot_to_print] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat2_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat2_dims[1]; ++j) {
        //        cout << mat2[ mat2_dims[1] * i + j ][slot_to_print] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        /*
         * Set up plaintexts
         */
        vector<Plaintext> mat1_pt(mat1_elem_no);
        vector<Plaintext> mat2_pt(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            bencd.encode(mat1[i], mat1_pt[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            bencd.encode(mat2[i], mat2_pt[i]);

        /*
         * Encrypt
         */
        vector<Ciphertext> mat1_elems_ct(mat1_elem_no);
        vector<Ciphertext> mat2_elems_ct(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            enc.encrypt(mat1_pt[i], mat1_elems_ct[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            enc.encrypt(mat2_pt[i], mat2_elems_ct[i]);

        Matrix mat1_ct(mat1_dims[0], mat1_dims[1], mat1_elems_ct);
        Matrix mat2_ct(mat2_dims[0], mat2_dims[1], mat2_elems_ct);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
                }
                );

        /*
         * Perform encrypted matrix multiplication
         */
        Timer t;
        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);

        t.tic();
        Matrix mat3_ct = mat1_ct.matmul(eval, rk, mat2_ct);
        t.toc("HE matrix multiplication time");

        vector<Ciphertext> mat3_elems_ct = mat3_ct.get_elems();

        /*
         * Decrypt result
         */
        vector<Plaintext> mat3_pt(mat3_elem_no);
        vector<vector<uint64_t>> mat3(mat3_elem_no, vector<uint64_t>(slot_no));
        for (size_t i = 0; i < mat3_elem_no; ++i) {
            //cout << "Noise budget: " << dec.invariant_noise_budget(mat3_elems_ct[i]) << '\n';
            dec.decrypt(mat3_elems_ct[i], mat3_pt[i]);
            bencd.decode(mat3_pt[i], mat3[i]);
        }

        /*
         * Print result
         */
        cout << "Initial noise budget: " << dec.invariant_noise_budget(mat1_elems_ct[0]) << '\n';
        cout << "Final noise budget: " << dec.invariant_noise_budget(mat3_elems_ct[0]) << '\n';
        cout << '\n';

        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < mat3_dims[0]; ++i) {
            for (size_t j = 0; j < mat3_dims[1]; ++j) {
                cout << mat3[mat3_dims[1] * i + j][slot_to_print] << ' ';
            }
            cout << '\n';
        }
        cout << ']' << "\n\n";

    }

    void bench_he_batch_matmul_ckks() // minor differences from the above
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 40);

        /*
         * Set up keys, encryptor, decryptor, CKKS encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data (a lot of pairs of matrices to be multiplied in parallel)
         */
        size_t slot_no = cencd.slot_count();
        vector<size_t> mat1_dims({5, 5}), mat2_dims({5, 5});
        size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
        size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);
        vector<vector<Complex>> mat1(mat1_elem_no, vector<Complex>(slot_no));
        vector<vector<Complex>> mat2(mat2_elem_no, vector<Complex>(slot_no));
        for (size_t s = 0; s < slot_no; ++s) {
            for (size_t i = 0; i < mat1_elem_no; ++i)
                mat1[i][s] = Complex(-1.4 * i + 2.2 * s + 7.1, 0.4 * i - 53.6 * s + 80.3);
            for (size_t i = 0; i < mat2_elem_no; ++i)
                mat2[i][s] = Complex(-5.9 * i + 0.8 * s - 119.1, 0.7 * i + 1.8 * s + 4.5);
        }

        /*
         * Print operand matrices
         */
        size_t slot_to_print = 0;
        //cout << "Print operand matrices:" << '\n';
        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat1_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat1_dims[1]; ++j) {
        //        cout << mat1[ mat1_dims[1] * i + j ][slot_to_print] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        //cout << '[' << '\n';
        //for (size_t i = 0; i < mat2_dims[0]; ++i) {
        //    for (size_t j = 0; j < mat2_dims[1]; ++j) {
        //        cout << mat2[ mat2_dims[1] * i + j ][slot_to_print] << ' ';
        //    }
        //    cout << '\n';
        //}
        //cout << ']' << "\n\n";

        /*
         * Set up plaintexts
         */
        vector<Plaintext> mat1_pt(mat1_elem_no);
        vector<Plaintext> mat2_pt(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            cencd.encode(mat1[i], scale, mat1_pt[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            cencd.encode(mat2[i], scale, mat2_pt[i]);

        /*
         * Encrypt
         */
        vector<Ciphertext> mat1_elems_ct(mat1_elem_no);
        vector<Ciphertext> mat2_elems_ct(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            enc.encrypt(mat1_pt[i], mat1_elems_ct[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            enc.encrypt(mat2_pt[i], mat2_elems_ct[i]);

        Matrix mat1_ct(mat1_dims[0], mat1_dims[1], mat1_elems_ct);
        Matrix mat2_ct(mat2_dims[0], mat2_dims[1], mat2_elems_ct);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
                }
                );

        /*
         * Perform encrypted matrix multiplication
         */
        Timer t;
        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);

        t.tic();
        Matrix mat3_ct = mat1_ct.matmul(eval, rk, mat2_ct);
        t.toc("HE matrix multiplication time");

        vector<Ciphertext> mat3_elems_ct = mat3_ct.get_elems();

        /*
         * Decrypt result
         */
        vector<Plaintext> mat3_pt(mat3_elem_no);
        vector<vector<Complex>> mat3(mat3_elem_no, vector<Complex>(slot_no));
        for (size_t i = 0; i < mat3_elem_no; ++i) {
            //cout << "Noise budget: " << dec.invariant_noise_budget(mat3_elems_ct[i]) << '\n';
            dec.decrypt(mat3_elems_ct[i], mat3_pt[i]);
            cencd.decode(mat3_pt[i], mat3[i]);
        }

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < mat3_dims[0]; ++i) {
            for (size_t j = 0; j < mat3_dims[1]; ++j) {
                cout << mat3[mat3_dims[1] * i + j][slot_to_print] << "   ";
            }
            cout << '\n';
        }
        cout << ']' << "\n\n";

    }

    void bench_he_matpow()
    {
        /*
         * Set up the encryption parameters (enabling batching) and create context
         */
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        int plain_modulus_bit_no = 32;
        parms.set_plain_modulus(1 << plain_modulus_bit_no);
        SEALContext ctx(parms);
        //cout << "Parameter validation: " << ctx.parameter_error_message() << '\n';
        //print_parameters(ctx); cout << '\n';
        //cout << "Batching enabled: " << ctx.first_context_data()->qualifiers().using_batching << '\n';

        /*
         * Set up keys, encryptor, decryptor, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        Evaluator eval(ctx);

        /*
         * Set up data (matrix, power)
         */
        vector<size_t> mat1_dims({5, 5});
        size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
        vector<uint64_t> mat1(mat1_elem_no);
        for (size_t i = 0; i < mat1.size(); ++i)
            mat1[i] = i+7;

        int powr = 5;

        /*
         * Set up plaintexts
         */
        vector<Plaintext> mat1_pt(mat1_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            mat1_pt[i] = Plaintext(he::util::uint64_to_hex_string(mat1[i]));

        /*
         * Encrypt
         */
        vector<Ciphertext> mat1_elems_ct(mat1_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            enc.encrypt(mat1_pt[i], mat1_elems_ct[i]);

        Matrix mat1_ct(mat1_dims[0], mat1_dims[1], mat1_elems_ct);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                stringstream ss;
                uint64_t rslt;
                dec.decrypt(ct, pt);
                ss.str(pt.to_string());
                ss >> hex >> rslt;
                cout << "Peek value (" << what_val << ") : " << rslt << '\n';
                }
                );

        /*
         * Perform encrypted matrix multiplication
         */
        Timer t;

        t.tic();
        Matrix mat2_ct = mat1_ct.matmul_pow(eval, rk, powr);
        t.toc("HE matrix power time");

        vector<Ciphertext> mat2_elems_ct = mat2_ct.get_elems();

        /*
         * Decrypt result
         */
        vector<size_t> mat2_dims(mat1_dims);
        size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);
        vector<Plaintext> mat2_pt(mat2_elem_no);
        for (size_t i = 0; i < mat2_elem_no; ++i) {
            dec.decrypt(mat2_elems_ct[i], mat2_pt[i]);
        }

        /*
         * Print result
         */
        cout << "Initial noise budget: " << dec.invariant_noise_budget(mat1_elems_ct[0]) << '\n';
        cout << "Final noise budget: " << dec.invariant_noise_budget(mat2_elems_ct[0]) << '\n';
        cout << '\n';

        stringstream ss;
        uint64_t rslt;
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < mat2_dims[0]; ++i) {
            for (size_t j = 0; j < mat2_dims[1]; ++j) {
                ss.str(mat2_pt[ mat2_dims[1] * i + j ].to_string());
                ss >> hex >> rslt;
                ss.clear();
                cout << rslt << ' ';
            }
            cout << '\n';
        }
        cout << ']' << "\n\n";

    }

    void bench_he_sum_elems()
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 15;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                    60,
                    40, 40, 40, 40, 40,
                    60
                    }));
        double scale = pow(2.0, 40);
        SEALContext ctx(parms);

        /*
         * Set up keys, encryptor, decryptor, CKKS encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        GaloisKeys gk;
        kgen.create_galois_keys(gk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data
         */
        vector<double> op({-11, 8, 8, 7, -10, 80, 4, 2, 3, 1});

        /*
         * Set up plaintexts
         */
        Plaintext op_pt;
        cencd.encode(op, scale, op_pt);

        /*
         * Encrypt
         */
        Ciphertext op_ct;
        enc.encrypt(op_pt, op_ct);

        /*
         * Perform encrypted operation
         */
        BatchedVector bvec(op.size(), move(op_ct));

        bvec.sum_elems_inplace(eval, gk);

        /*
         * Decrypt and print
         */
        auto decrypt_and_print(
            [&](const Ciphertext &res_ct)
            {
                /*
                 * Decrypt result
                 */
                Plaintext res_pt;
                vector<double> res;
                dec.decrypt(res_ct, res_pt);
                cencd.decode(res_pt, res);

                /*
                 * Print result
                 */
                for (size_t i = 0; i < 8; ++i)
                    cout << res[i] << ' ';

                cout << " ... ";

                for (size_t i = res.size() - 4; i < res.size(); ++i)
                    cout << res[i] << ' ';

                cout << '\n';
            });

        cout << "dim: " << bvec.get_dim() << '\n';
        decrypt_and_print(bvec.get_bvec());
    }

    void bench_he_least_squares_2d()
    {
        Timer t;

        /*
         * Set up the encryption parameters and create context
         */
        t.tic();
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 15;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                    60,
                    40, 40, 40, 40, 40,
                    40, 40, 40, 40, 40,
                    40, 40, 40, 40, 40,
                    60
                    }));
        double scale = pow(2.0, 40);
        SEALContext ctx(parms);
        t.toc("parms & ctx");

        /*
         * Set up keys, encryptor, decryptor, CKKS encoder, evaluator
         */
        t.tic();
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        t.toc("secret key");
        t.tic();
        PublicKey pk;
        kgen.create_public_key(pk);
        t.toc("public key");
        t.tic();
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        t.toc("relin key");
        t.tic();
        GaloisKeys gk;
        kgen.create_galois_keys(gk);
        t.toc("galois key");
        t.tic();
        Encryptor enc(ctx, pk);
        t.toc("encryptor");
        t.tic();
        Decryptor dec(ctx, sk);
        t.toc("decryptor");
        t.tic();
        CKKSEncoder cencd(ctx);
        t.toc("ckks encoder");
        t.tic();
        Evaluator eval(ctx);
        t.toc("evaluator");

        /*
         * Set up data
         */
        vector<double> x {6, 5.8, 6.5, 5.4, 6.8};
        vector<double> y {2, 1.4, 2.4, 1.5, 2.4};

        assert(x.size() == y.size());
        size_t n = x.size();

        /*
         * Set up plaintexts
         */
        Plaintext x_pt, y_pt;
        cencd.encode(x, scale, x_pt);
        cencd.encode(y, scale, y_pt);

        /*
         * Encrypt
         */
        t.tic();
        Ciphertext x_ct, y_ct;
        enc.encrypt(x_pt, x_ct);
        enc.encrypt(y_pt, y_ct);
        t.toc("encrypt");

        /*
         * Perform encrypted operation
         */
        BatchedVector x_ctv(n, move(x_ct));
        BatchedVector y_ctv(n, move(y_ct));

        t.tic();
        Ciphertext sum_x_ct = x_ctv.sum_elems(eval, gk).get_bvec();
        t.toc();
        t.tic();
        Ciphertext sum_y_ct = y_ctv.sum_elems(eval, gk).get_bvec();
        t.toc();
        t.tic();
        Ciphertext sum_xx_ct = x_ctv.square(eval, rk).sum_elems(eval, gk).get_bvec();
        t.toc();
        t.tic();
        Ciphertext sum_xy_ct = (eval% rk% x_ctv * y_ctv).sum_elems(eval, gk).get_bvec();
        t.toc();

        // Denominator
        t.tic();
        Plaintext n_pt;
        cencd.encode(n, sum_xx_ct.parms_id(), sum_xx_ct.scale(), n_pt);
        Ciphertext n_sum_xx_ct = eval% sum_xx_ct * n_pt;
        n_sum_xx_ct ^= eval; // rescale

        Ciphertext sum_x_sqr_ct;
        eval.square(sum_x_ct, sum_x_sqr_ct);
        sum_x_sqr_ct &= eval% rk; // relin
        sum_x_sqr_ct ^= eval; // rescale

        Plaintext one_pt;
        cencd.encode(1, sum_x_sqr_ct.parms_id(), sum_x_sqr_ct.scale(), one_pt);
        sum_x_sqr_ct *= eval% one_pt;
        sum_x_sqr_ct ^= eval; // rescale

        Ciphertext denom_ct = eval% n_sum_xx_ct - sum_x_sqr_ct;
        cout << log2(denom_ct.scale()) << '\n';

        // FIXME: check why inverse is affected by the rest batch elements
        Plaintext one_pt_;
        cencd.encode(vector<double>{1}, denom_ct.parms_id(), denom_ct.scale(), one_pt_);
        denom_ct *= eval% one_pt_;
        denom_ct ^= eval;

        Ciphertext denom_inv_ct = he::math::signed_inv(cencd, eval, rk, denom_ct, 0.05, 6);
        cout << log2(denom_inv_ct.scale()) << '\n';
        t.toc();

        // numerator of a
        Ciphertext n_sum_xy_ct = eval% sum_xy_ct * n_pt;
        n_sum_xy_ct ^= eval; // rescale

        Ciphertext sum_x_sum_y_ct = eval% sum_x_ct * sum_y_ct;
        sum_x_sum_y_ct &= eval% rk; // relin
        sum_x_sum_y_ct ^= eval; // rescale

        sum_x_sum_y_ct *= eval% one_pt;
        sum_x_sum_y_ct ^= eval; // rescale

        Ciphertext a_num_ct = eval% n_sum_xy_ct - sum_x_sum_y_ct;

        // numerator of b
        cencd.encode(1, sum_y_ct.parms_id(), sum_y_ct.scale(), one_pt);
        Ciphertext sum_y_sum_xx_ct = sum_y_ct;
        sum_y_sum_xx_ct *= eval% one_pt;
        sum_y_sum_xx_ct ^= eval; // rescale

        sum_y_sum_xx_ct *= eval% sum_xx_ct;
        sum_y_sum_xx_ct &= eval% rk;
        sum_y_sum_xx_ct ^= eval; // rescale

        Ciphertext sum_x_sum_xy_ct = sum_x_ct;
        sum_x_sum_xy_ct *= eval% one_pt;
        sum_x_sum_xy_ct ^= eval; // rescale

        sum_x_sum_xy_ct *= eval% sum_xy_ct;
        sum_x_sum_xy_ct &= eval% rk;
        sum_x_sum_xy_ct ^= eval; // rescale

        Ciphertext b_num_ct = eval% sum_y_sum_xx_ct - sum_x_sum_xy_ct;

        // a, b
        he::util::reach_chain_level(ctx, cencd, eval, one_pt, vector{&a_num_ct, &b_num_ct}, denom_inv_ct);

        Ciphertext a_ct = eval% a_num_ct * denom_inv_ct;
        a_ct &= eval% rk; // relin
        a_ct ^= eval; // rescale

        Ciphertext b_ct = eval% b_num_ct * denom_inv_ct;
        b_ct &= eval% rk; // relin
        b_ct ^= eval; // rescale

        /*
         * Decrypt and print
         */
        auto decrypt_and_print(
            [&](const Ciphertext &res_ct)
            {
                /*
                 * Decrypt result
                 */
                Plaintext res_pt;
                vector<double> res;
                dec.decrypt(res_ct, res_pt);
                cencd.decode(res_pt, res);

                /*
                 * Print result
                 */
                for (size_t i = 0; i < 8; ++i)
                    cout << res[i] << ' ';

                cout << " ... ";

                for (size_t i = res.size() - 4; i < res.size(); ++i)
                    cout << res[i] << ' ';

                cout << '\n';
            });

        decrypt_and_print(denom_ct);
        decrypt_and_print(denom_inv_ct);
        decrypt_and_print(a_num_ct);
        decrypt_and_print(b_num_ct);

        decrypt_and_print(a_ct);
        decrypt_and_print(b_ct);
    }

    void bench_he_batched_matmul_ckks() // minor differences from the above
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 40);

        /*
         * Set up keys, encryptor, decryptor, CKKS encoder, evaluator
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        PublicKey pk;
        kgen.create_public_key(pk);
        RelinKeys rk;
        kgen.create_relin_keys(rk);
        GaloisKeys gk;
        kgen.create_galois_keys(gk);
        Encryptor enc(ctx, pk);
        Decryptor dec(ctx, sk);
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        /*
         * Set up data (a lot of pairs of matrices to be multiplied in parallel)
         */
        size_t slot_no = cencd.slot_count();
        size_t mat1_row_no = 1 << 6;
        size_t mat1_col_no = 1 << 6;
        size_t mat2_row_no = mat1_row_no;
        size_t mat2_col_no = mat1_col_no;

        vector<vector<Complex>> mat1(mat1_col_no, vector<Complex>(slot_no));

        int counter = 2;
        for (size_t c = 0; c < mat1_col_no; ++c) {
            for (size_t r = 0; r < slot_no; ++r)
                mat1[c][r] = Complex(counter + r % mat1_row_no, 0);

            counter += mat1_row_no;
        }

#define PRINT 0

#if PRINT == 1
        for (size_t c = 0; c < mat1_col_no; ++c) {
            for (size_t r = 0; r < mat1_row_no; ++r)
                cout << mat1[c][r] << "    ";

            cout << '\n';
        }
        cout << '\n';
        cout << '\n';
        cout << '\n';
#endif

        /*
         * Set up plaintexts
         */
        vector<Plaintext> mat1_cols_pt(mat1_col_no);
        for (size_t i = 0; i < mat1_cols_pt.size(); ++i)
            cencd.encode(mat1[i], scale, mat1_cols_pt[i]);

        /*
         * Encrypt
         */
        vector<Ciphertext> mat1_cols_ct(mat1_col_no);
        for (size_t i = 0; i < mat1_col_no; ++i)
            enc.encrypt(mat1_cols_pt[i], mat1_cols_ct[i]);

        vector<BatchedVector> mat1_cols_bvec;
        mat1_cols_bvec.reserve(mat1_col_no);

        for (size_t i = 0; i < mat1_col_no; ++i)
            mat1_cols_bvec.emplace_back(mat1_row_no, move(mat1_cols_ct[i]));

#define COL_OR_DIAG 0

#if COL_OR_DIAG == 0
        BatchedMatrix mat1_bmat(BatchedMatrix::BatchingType::col, move(mat1_cols_bvec));
        BatchedMatrix mat2_bmat = mat1_bmat;
        mat2_bmat.transp();
#else
        BatchedMatrix mat1_bmat(BatchedMatrix::BatchingType::diag, mat1_cols_bvec);
        BatchedMatrix mat2_bmat(BatchedMatrix::BatchingType::col, move(mat1_cols_bvec));
#endif

        /*
         * Perform encrypted matrix multiplication
         */
        Timer t;

        t.tic();
        BatchedMatrix mat3_bmat = mat1_bmat.matmul(eval, rk, gk, mat2_bmat);
        t.toc("HE matrix multiplication time");

        /*
         * Decrypt result
         */
        size_t mat3_row_no = mat1_row_no;
        size_t mat3_col_no = mat2_row_no;

        Plaintext mat3_diag_pt;

        vector<vector<Complex>> mat3(mat3_col_no, vector<Complex>(slot_no));

        for (size_t i = 0; i < mat3_col_no; ++i) {
            dec.decrypt(mat3_bmat[i].get_bvec(), mat3_diag_pt);
            cencd.decode(mat3_diag_pt, mat3[i]);
        }

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << '[' << '\n';

#if PRINT == 1
        for (size_t c = 0; c < mat3_col_no; ++c) {
            for (size_t r = 0; r < mat3_row_no; ++r)
                cout << mat3[c][r] << "    ";

            cout << '\n';
        }
#endif

        cout << ']' << "\n\n";

    }

} // namespace

void matrix_operations_demo(const char **argv)
{
    string delim("###########################################################");
    cout << '\n';
    cout << '\n' << delim << "\n\n";

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        bench_he_##demo_name(); \
    else


    RUN_DEMO_IFELSE(op)
    RUN_DEMO_IFELSE(elemwise_square)
    RUN_DEMO_IFELSE(matmul)
    RUN_DEMO_IFELSE(batch_matmul_bfv)
    RUN_DEMO_IFELSE(batch_matmul_ckks)
    RUN_DEMO_IFELSE(matpow)
    RUN_DEMO_IFELSE(sum_elems)
    RUN_DEMO_IFELSE(least_squares_2d)
    RUN_DEMO_IFELSE(batched_matmul_ckks)
        cout << "No such demo for " << argv[1] << "." << '\n';


    cout << '\n' << delim << "\n\n";
}
