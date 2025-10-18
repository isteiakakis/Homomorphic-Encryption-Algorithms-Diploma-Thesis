#include "seal/seal.h"
#include "he_linalg.h"

using namespace std;
using namespace seal;
using namespace he::linalg;
using Complex = complex<double>;

namespace
{
    void cl_srv_he_batch_matmul()
    {
        /*
         * Client-server shared streams
         */
        stringstream net_stream;

        SecretKey sk;

        vector<size_t> mat1_dims({5, 5}), mat2_dims({5, 5});
        size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
        size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);

        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);

        /*
         * Server:
         * Parameters
         */
        {
            EncryptionParameters parms(scheme_type::ckks);
            size_t poly_modulus_degree = 1 << 13;
            parms.set_poly_modulus_degree(poly_modulus_degree);
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

            /* Serialization */
            parms.save(net_stream);

            net_stream.seekp(0);
        }

        /*
         * Client:
         * Keys, encode, encrypt
         */
        {
            EncryptionParameters parms;
            parms.load(net_stream);

            net_stream.seekg(0);

            parms.save(net_stream);

            SEALContext ctx(parms);

            KeyGenerator kgen(ctx);
            sk = kgen.secret_key();
            PublicKey pk;
            kgen.create_public_key(pk);

            /* Relinearization key */
            Serializable<RelinKeys> rk = kgen.create_relin_keys();
            rk.save(net_stream);

            /* Encode */
            double scale = pow(2.0, 40);
            CKKSEncoder cencd(ctx);

            size_t slot_no = cencd.slot_count();
            //vector<size_t> mat1_dims({5, 5}), mat2_dims({5, 5});
            //size_t mat1_elem_no(mat1_dims[0] * mat1_dims[1]);
            //size_t mat2_elem_no(mat2_dims[0] * mat2_dims[1]);
            vector<vector<Complex>> mat1(mat1_elem_no, vector<Complex>(slot_no));
            vector<vector<Complex>> mat2(mat2_elem_no, vector<Complex>(slot_no));
            for (size_t s = 0; s < slot_no; ++s) {
                for (size_t i = 0; i < mat1.size(); ++i)
                    mat1[i][s] = Complex(1.4 * i + 2.2 * s + 7.1, 0.4 * i + 0.6 * s + 1.3);
                for (size_t i = 0; i < mat2.size(); ++i)
                    mat2[i][s] = Complex(5.9 * i + 0.8 * s + 9.1, 0.7 * i + 1.8 * s + 4.5);
            }

            vector<Plaintext> mat1_pt(mat1_elem_no);
            vector<Plaintext> mat2_pt(mat2_elem_no);
            for (size_t i = 0; i < mat1_elem_no; ++i)
                cencd.encode(mat1[i], scale, mat1_pt[i]);
            for (size_t i = 0; i < mat2_elem_no; ++i)
                cencd.encode(mat2[i], scale, mat2_pt[i]);

            /* 1st operand: Encrypt and serialize */
            Encryptor enc(ctx, pk);
            for (size_t i = 0; i < mat1_elem_no; ++i)
                enc.encrypt(mat1_pt[i]).save(net_stream);

            /* 2nd operand: Encrypt and serialize */
            for (size_t i = 0; i < mat2_elem_no; ++i)
                enc.encrypt(mat2_pt[i]).save(net_stream);

            net_stream.seekp(0);
        }

        /*
         * Server:
         * Encrypted computation
         */
        {
            EncryptionParameters parms;
            parms.load(net_stream);

            parms.save(net_stream);

            SEALContext ctx(parms);

            RelinKeys rk;
            rk.load(ctx, net_stream);

            vector<Ciphertext> mat1_elems_ct(mat1_elem_no);
            vector<Ciphertext> mat2_elems_ct(mat2_elem_no);

            /* Deserialization */
            for (size_t i = 0; i < mat1_elem_no; ++i)
                mat1_elems_ct[i].load(ctx, net_stream);
            for (size_t i = 0; i < mat2_elem_no; ++i)
                mat2_elems_ct[i].load(ctx, net_stream);

            net_stream.seekg(0);

            /* Encrypted computation */
            Evaluator eval(ctx);
            Matrix mat1_ct(mat1_dims[0], mat1_dims[1], mat1_elems_ct);
            Matrix mat2_ct(mat2_dims[0], mat2_dims[1], mat2_elems_ct);

            Matrix mat3_ct = mat1_ct.matmul(eval, rk, mat2_ct);

            vector<Ciphertext> mat3_elems_ct = mat3_ct.get_elems();

            /* Serialize the result */
            for (size_t i = 0; i < mat3_elem_no; ++i)
                mat3_elems_ct[i].save(net_stream);

            net_stream.seekp(0);
        }

        /*
         * Client:
         * Decrypt result
         */
        {
            EncryptionParameters parms;
            parms.load(net_stream);
            SEALContext ctx(parms);

            Decryptor dec(ctx, sk);
            CKKSEncoder cencd(ctx);

            /* Deserialize the result ciphertext */
            vector<Ciphertext> mat3_elems_ct(mat3_elem_no);
            for (size_t i = 0; i < mat3_elem_no; ++i)
                mat3_elems_ct[i].load(ctx, net_stream);

            /* Decrypt, decode */
            size_t slot_no = cencd.slot_count();
            vector<Plaintext> mat3_pt(mat3_elem_no);
            vector<vector<Complex>> mat3(mat3_elem_no, vector<Complex>(slot_no));
            for (size_t i = 0; i < mat3_elem_no; ++i) {
                dec.decrypt(mat3_elems_ct[i], mat3_pt[i]);
                cencd.decode(mat3_pt[i], mat3[i]);
            }

            size_t slot_to_print = 0;
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
    }

    void orig_example()
    {
        /*
         * Client-server shared streams
         */
        stringstream parms_stream;
        stringstream data_stream;
        stringstream sk_stream;

        /*
         * Server:
         * Parameters
         */
        {
            EncryptionParameters parms(scheme_type::ckks);
            size_t poly_modulus_degree = 8192;
            parms.set_poly_modulus_degree(poly_modulus_degree);
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 50 }));

            /* Serialization */
            auto size = parms.save(parms_stream);
            cout << "EncryptionParameters: wrote " << size << " bytes" << endl;
        }

        /*
         * Client:
         * Context, keys
         */
        {
            EncryptionParameters parms;
            parms.load(parms_stream);

            // Seek to beginning because the same stream will be used to read the parameters repeatedly.
            parms_stream.seekg(0, parms_stream.beg);

            SEALContext context(parms);

            KeyGenerator kgen(context);
            auto sk = kgen.secret_key();
            PublicKey pk;
            kgen.create_public_key(pk);

            /* Save the secret key */
            sk.save(sk_stream);

            /* Relinearization key */
            Serializable<RelinKeys> rlk = kgen.create_relin_keys();
            rlk.save(data_stream);

            /* Encode */
            double scale = pow(2.0, 30);
            CKKSEncoder encoder(context);
            Plaintext plain1, plain2;
            encoder.encode(2.3, scale, plain1);
            encoder.encode(4.5, scale, plain2);

            /* 1st operand: Encrypt and serialize */
            Encryptor encryptor(context, pk);
            encryptor.encrypt(plain1).save(data_stream);

            /* 2nd operand: Encrypt symmetric (seeded state) and serialize */
            encryptor.set_secret_key(sk);
            encryptor.encrypt_symmetric(plain2).save(data_stream);
        }

        /*
         * Server:
         * Context, evaluator, encrypted computation
         */
        {
            EncryptionParameters parms;
            parms.load(parms_stream);
            parms_stream.seekg(0, parms_stream.beg);
            SEALContext context(parms);

            Evaluator evaluator(context);

            RelinKeys rlk;
            Ciphertext encrypted1, encrypted2;

            /* Deserialization */
            rlk.load(context, data_stream);
            encrypted1.load(context, data_stream);
            encrypted2.load(context, data_stream);

            /* Encrypted computation */
            Ciphertext encrypted_prod;
            evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
            evaluator.relinearize_inplace(encrypted_prod, rlk);
            evaluator.rescale_to_next_inplace(encrypted_prod);

            /* Serialize the result */
            data_stream.seekp(0, parms_stream.beg);
            data_stream.seekg(0, parms_stream.beg);
            encrypted_prod.save(data_stream);
        }

        /*
         * Client:
         * Decrypt result
         */
        {
            EncryptionParameters parms;
            parms.load(parms_stream);
            parms_stream.seekg(0, parms_stream.beg);
            SEALContext context(parms);

            /* Deserialize the secret key */
            SecretKey sk;
            sk.load(context, sk_stream);
            Decryptor decryptor(context, sk);
            CKKSEncoder encoder(context);

            /* Deserialize the result ciphertext */
            Ciphertext encrypted_result;
            encrypted_result.load(context, data_stream);

            /* Decrypt, decode */
            Plaintext plain_result;
            decryptor.decrypt(encrypted_result, plain_result);
            vector<double> result;
            encoder.decode(plain_result, result);
        }
    }
} // namespace

void client_server_rookie_demo(const char **argv)
{
    string delim("###########################################################");
    cout << '\n';
    cout << '\n' << delim << "\n\n";

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        demo_name(); \
    else


    RUN_DEMO_IFELSE(cl_srv_he_batch_matmul)
    RUN_DEMO_IFELSE(orig_example)
        cout << "No such demo for " << argv[1] << "." << '\n';


    cout << '\n' << delim << "\n\n";
}
