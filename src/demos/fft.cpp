#include "he_fft.h"
#include "seal/seal.h"
#include "tic_toc.h"
#include <cmath>

using namespace std;
using namespace seal;
using namespace he::fft;
using Complex = complex<double>;

namespace
{
    void bench_he_fft()
    {
        /*
         * Encryption parameters and context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 30);

        /*
         * Keys, encryptor, decryptor, CKKS encoder, evaluator
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
        size_t slot_no = cencd.slot_count();
        size_t vec_elem_no = 128; // power of 2
        vector<vector<Complex>> vec(vec_elem_no, vector<Complex>(slot_no));
        for (size_t s = 0; s < slot_no; ++s) {
            for (size_t i = 0; i < vec_elem_no; ++i)
                vec[i][s] = 2.2 * i - 10.8 * s + 513.1;
        }

        /*
         * Print operand
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
         * Plaintext
         */
        vector<Plaintext> vec_pt(vec_elem_no);
        for (size_t i = 0; i < vec_elem_no; ++i)
            cencd.encode(vec[i], scale, vec_pt[i]);

        /*
         * Encrypt
         */
        vector<Ciphertext> vec_ct(vec_elem_no);
        for (size_t i = 0; i < vec_elem_no; ++i)
            enc.encrypt(vec_pt[i], vec_ct[i]);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
                [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
                }
                );

        /*
         * Perform encrypted FFT
         */
        Timer t;
        size_t vecr_elem_no = vec_elem_no;

        t.tic();
        vector<Ciphertext> vecr_ct = fft(cencd, eval, vec_ct);
        t.toc("HE FFT time");

        /*
         * Decrypt
         */
        vector<Plaintext> vecr_pt(vecr_elem_no);
        vector<vector<Complex>> vecr(vecr_elem_no);
        for (size_t i = 0; i < vecr_elem_no; ++i) {
            dec.decrypt(vecr_ct[i], vecr_pt[i]);
            cencd.decode(vecr_pt[i], vecr[i]);
        }

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < vecr.size(); ++i) {
            cout << vecr[i][slot_to_print] << '\n';
        }
        cout << ']' << "\n\n";
    }

    void bench_he_bfft()
    {
        /*
         * Encryption parameters and context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                    60,
                    31, 30, 30, 30, 30,
                    30, 30, 30, 30, 30,
                    60
                    }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 30);

        /*
         * Keys, encryptor, decryptor, CKKS encoder, evaluator
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
        size_t n = 128;
        if (n > cencd.slot_count()) {
            cout << "Too many data" << '\n';
            return;
        }

        vector<Complex> data;
        data.reserve(n);
        for (size_t i = 0; i < data.capacity(); ++i)
            data.push_back(i + 7.1);

        vector<Complex> vec;
        vec.reserve(cencd.slot_count());
        for (size_t i = 0; i < vec.capacity()/data.size(); ++i)
            vec.insert(vec.end(), data.begin(), data.end());

        /*
         * Plaintext
         */
        Plaintext vec_pt;
        cencd.encode(vec, scale, vec_pt);

        /*
         * Encrypt
         */
        Ciphertext vec_ct;
        enc.encrypt(vec_pt, vec_ct);

        /* Help function for a quick peek on a ciphertext */
        auto peek_val (
            [&dec](const Ciphertext &ct, const string_view what_val = "") {
                Plaintext pt;
                dec.decrypt(ct, pt);
                cout << "Peek value (" << what_val << ") : " << pt.to_string() << '\n';
            });

        /*
         * Perform encrypted FFT
         */
        Timer t;

        t.tic();
        Ciphertext vecr_ct = bfft(cencd, eval, gk, vec_ct, n);
        t.toc("HE bFFT time");

        /*
         * Decrypt, decode
         */
        Plaintext vecr_pt;
        vector<Complex> vecr;

        dec.decrypt(vecr_ct, vecr_pt);
        cencd.decode(vecr_pt, vecr);
        vecr.resize(n);

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << '[' << '\n';

        auto rev_bits(
            [](int num, int bit_size) -> int
            {
                // Reverse the bits of the number `num` with `bit_size` bits
                int reversed_num = 0;
                for (size_t _ = 0; _ < bit_size; ++_) {
                    reversed_num = (reversed_num << 1) | (num & 1);
                    num >>= 1;
                }
                return reversed_num;
            });

        for (size_t i = 0; i < vecr.size(); ++i) {
            cout << vecr[rev_bits(i, round(log2(n-1)))] << '\n';
        }

        cout << ']' << "\n\n";
    }
} // namespace

void fft_demo(const char **argv)
{
    string delim("###########################################################");
    cout << '\n';
    cout << '\n' << delim << "\n\n";

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        bench_he_##demo_name(); \
    else


    RUN_DEMO_IFELSE(fft)
    RUN_DEMO_IFELSE(bfft)
        cout << "No such demo for " << argv[1] << "." << '\n';


    cout << '\n' << delim << "\n\n";
}
