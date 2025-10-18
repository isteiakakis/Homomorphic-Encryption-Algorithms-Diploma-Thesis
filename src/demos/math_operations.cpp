#include "he_math.h"
#include "seal/seal.h"
#include "tic_toc.h"

using namespace std;
using namespace seal;
using namespace he::math;
using namespace he::operators;

namespace
{
    void bench_he_all(int chain_levels)
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 15;
        parms.set_poly_modulus_degree(poly_modulus_degree);

        if (chain_levels == 1) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                //30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 2) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, //30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 3) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, //30, 30, 30,
                60
            }));
        } else if (chain_levels == 4) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, //30, 30,
                60
            }));
        } else if (chain_levels == 5) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, //30,
                60
            }));
        } else if (chain_levels == 6) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 7) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30, 30,
                30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 8) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30, 30,
                30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 9) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31, 30,
                30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 10) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31, 31,
                30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 11) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30, 31,
                31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 12) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31, 30,
                31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 13) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30, 31,
                30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 14) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31, 30,
                31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 15) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                //31,
                30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 16) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 17) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31, 31,
                30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 18) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31, 31,
                31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 19) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31, 31,
                31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 20) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30, 31,
                31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 21) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30, 30,
                31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 22) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30, 30,
                30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 23) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31, 30,
                30, 30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 24) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31, 31,
                30, 30, 30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 25) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                //31,
                31, 30, 30, 30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        } else if (chain_levels == 26) {
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                60,
                31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                30, 30, 30, 30, 30,
                60
            }));
        }

        double scale = pow(2.0, 30);
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
        double op1 = 5;
        double op2 = -8;

        /*
         * Set up plaintexts
         */
        Plaintext op1_pt, op2_pt;
        cencd.encode({op1}, scale, op1_pt);
        cencd.encode({op2}, scale, op2_pt);

        /*
         * Encrypt
         */
        Ciphertext op1_ct, op2_ct;
        enc.encrypt(op1_pt, op1_ct);
        enc.encrypt(op2_pt, op2_ct);

        /*
         * Perform encrypted operation
         */

        auto decrypt_and_print(
            [&](const Ciphertext &res_ct)
            {
                /*
                 * Decrypt result
                 */
                Plaintext res_pt;
                vector<double> res_;
                dec.decrypt(res_ct, res_pt);
                cencd.decode(res_pt, res_);
                double res = res_[0];

                /*
                 * Print result
                 */
                cout << "Encrypted computation result: " << res << '\n';
                cout << '\n';
            });

        Ciphertext res_ct;
        Timer t;
        double c;
        double prim_op;
        double ptct_op;
        double ctct_op;

        cout << "pt-ct add" << '\n';
        t.tic();
        res_ct = eval% op1_ct + op2_pt;
        ptct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "ct-ct add" << '\n';
        t.tic();
        res_ct = eval% op1_ct + op2_ct;
        ctct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "----> ADD: " << ptct_op << "    " << ctct_op << '\n';
        cout << '\n';

        cout << "pt-ct mult" << '\n';
        t.tic();
        res_ct = eval% op1_ct * op2_pt;
        ptct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "ct-ct mult" << '\n';
        t.tic();
        res_ct = eval% op1_ct * op2_ct;
        ctct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "----> MULT: " << ptct_op << "    " << ctct_op << '\n';
        cout << '\n';

        double relin_op;

        cout << "relin" << '\n';
        t.tic();
        res_ct &= eval% rk;
        relin_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "----> RELIN: " << relin_op << '\n';
        cout << '\n';

#if 0
        cout << "1/" << op1 << " = " << 1/op1 << '\n';
        t.tic();
        res_ct = signed_inv(cencd, eval, rk, op1_ct, 0.01, 7);
        t.tocr();
        decrypt_and_print(res_ct);

        cout << "1/sqrt(2*" << op1 << ") = " << 1/sqrt(2*op1) << '\n';
        t.tic();
        res_ct = inv_sqrt_twice(cencd, eval, rk, op1_ct, 0.01, 7);
        t.tocr();
        decrypt_and_print(res_ct);
#endif

    }

    void bench_he_all()
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 15;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                    60,
                    31, 31, 30, 30, 30, 31, 31, 31, 31, 30,
                    31, 30, 31, 30, 31, 31, 30, 30, 30, 30,
                    30, 30, 30, 30, 30,
                    60
                    }));
        double scale = pow(2.0, 30);
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
        double op1 = 5;
        double op2 = -8;

        /*
         * Set up plaintexts
         */
        Plaintext op1_pt, op2_pt;
        cencd.encode({op1}, scale, op1_pt);
        cencd.encode({op2}, scale, op2_pt);

        /*
         * Encrypt
         */
        Ciphertext op1_ct, op2_ct;
        enc.encrypt(op1_pt, op1_ct);
        enc.encrypt(op2_pt, op2_ct);

        /*
         * Perform encrypted operation
         */

        auto decrypt_and_print(
            [&](const Ciphertext &res_ct)
            {
                /*
                 * Decrypt result
                 */
                Plaintext res_pt;
                vector<double> res_;
                dec.decrypt(res_ct, res_pt);
                cencd.decode(res_pt, res_);
                double res = res_[0];

                /*
                 * Print result
                 */
                cout << "Encrypted computation result: " << res << '\n';
                cout << '\n';
            });

        Ciphertext res_ct;
        Timer t;
        double c;
        double prim_op;
        double ptct_op;
        double ctct_op;

        cout << "pt-ct add" << '\n';
        t.tic();
        res_ct = eval% op1_ct + op2_pt;
        ptct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "ct-ct add" << '\n';
        t.tic();
        res_ct = eval% op1_ct + op2_ct;
        ctct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "ADD: " << ptct_op << "    " << ctct_op << '\n';
        cout << '\n';

        cout << "pt-ct mult" << '\n';
        t.tic();
        res_ct = eval% op1_ct * op2_pt;
        ptct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "ct-ct mult" << '\n';
        t.tic();
        res_ct = eval% op1_ct * op2_ct;
        ctct_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "MULT: " << ptct_op << "    " << ctct_op << '\n';
        cout << '\n';

        double relin_op;

        cout << "relin" << '\n';
        t.tic();
        res_ct &= eval% rk;
        relin_op = t.tocr();
        decrypt_and_print(res_ct);

        cout << "RELIN: " << relin_op << '\n';
        cout << '\n';

#if 0
        cout << "1/" << op1 << " = " << 1/op1 << '\n';
        t.tic();
        res_ct = signed_inv(cencd, eval, rk, op1_ct, 0.01, 7);
        t.tocr();
        decrypt_and_print(res_ct);

        cout << "1/sqrt(2*" << op1 << ") = " << 1/sqrt(2*op1) << '\n';
        t.tic();
        res_ct = inv_sqrt_twice(cencd, eval, rk, op1_ct, 0.01, 7);
        t.tocr();
        decrypt_and_print(res_ct);
#endif

    }

    void bench_he_rot()
    {
        /*
         * Set up the encryption parameters and create context
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 15;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
                    60,
                    30, 30, 30, 30, 30,
                    60
                    }));
        double scale = pow(2.0, 30);
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
        vector<double> op({1, 2, 3, 4});

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

        int i = 1;
        op_ct <<= eval% gk% i;
        decrypt_and_print(op_ct);
    }
} // namespace

void math_operations_demo(const char **argv)
{
    string delim("###########################################################");
    cout << '\n';
    cout << '\n' << delim << "\n\n";

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        bench_he_##demo_name(); \
    else


#if 0
    RUN_DEMO_IFELSE(all)
    RUN_DEMO_IFELSE(rot)
        cout << "No such demo for " << argv[1] << "." << '\n';
#endif

    for (size_t i = 2; i <= 26; ++i) {
        cout << "CHAIN LEVELS: " << i << '\n';
        cout << '\n';
        bench_he_all(i);
        cout << "-------------------------------------------------------------------------" << '\n';
    }


    cout << '\n' << delim << "\n\n";
}
