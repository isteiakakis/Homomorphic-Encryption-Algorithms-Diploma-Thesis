#include "seal/seal.h"
#include "socket_io.h"
#include <cstring>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;
using namespace seal;
using Complex = complex<double>;

/* Client */

namespace
{
    int setup_client()
    {
        const char ip_addr[] = "127.0.0.1";
        int init_port = 8080;
        int fin_port = init_port + 20;
        int sock = 0;

        // Create socket file descriptor
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation error");
            exit(EXIT_FAILURE);
        }

        // Set IPv4 family
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;

        // Convert IP address from text to binary form
        if (inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address / Address not supported");
            close(sock);
            exit(EXIT_FAILURE);
        }


        int port;
        for (port = init_port; port <= fin_port; ++port) {
            serv_addr.sin_port = htons(port);

            // Connect to the server
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0)
                goto connect_success;

        }

        perror("Connection Failed");
        close(sock);
        exit(EXIT_FAILURE);

connect_success:

        cout << "Connection established." << "\n\n";

        return sock;
    }

    void client_side_simple(int sock)
    {
        cout << "Running the simple demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 40);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Generate keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operands
         */
        Complex op1(2.1, -9.5);
        Complex op2(-5.3, -8.7);

        /*
         * Encode the operands
         */
        CKKSEncoder cencd(ctx);

        Plaintext op1_pt, op2_pt;
        cencd.encode(op1, scale, op1_pt);
        cencd.encode(op2, scale, op2_pt);

        /*
         * Encrypt the operands
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        enc.encrypt_symmetric(op1_pt).save(onet_strm);
        enc.encrypt_symmetric(op2_pt).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertexts to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        Ciphertext res_ct;
        res_ct.load(ctx, inet_buf, inet_buf_sz);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        Plaintext res_pt;
        dec.decrypt(res_ct, res_pt);

        /*
         * Decode result
         */
        vector<Complex> res_;
        cencd.decode(res_pt, res_);
        Complex res = res_[0];

        /*
         * Print result
         */
        cout << op1 << " * " << op2 << " = " << res << '\n';
        cout << '\n';

    }

    void client_side_batch_matmul(int sock)
    {
        cout << "Running the batch matrix multiplication demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 13;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 40);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operands
         */
        CKKSEncoder cencd(ctx);
        size_t slot_no = cencd.slot_count();

        vector<size_t> mat1_dims({5, 5});
        vector<size_t> mat2_dims({5, 5});
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
         * Encode the operands
         */
        vector<Plaintext> mat1_pt(mat1_elem_no);
        vector<Plaintext> mat2_pt(mat2_elem_no);
        for (size_t i = 0; i < mat1_elem_no; ++i)
            cencd.encode(mat1[i], scale, mat1_pt[i]);
        for (size_t i = 0; i < mat2_elem_no; ++i)
            cencd.encode(mat2[i], scale, mat2_pt[i]);

        /*
         * Encrypt the operands
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        for (const auto &p : mat1_pt)
            enc.encrypt_symmetric(p).save(onet_strm);
        for (const auto &p : mat2_pt)
            enc.encrypt_symmetric(p).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertexts to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the dimensions of the operand matrices
        seal_byte matdims_bytes[4 * sizeof(size_t)];
        memcpy(matdims_bytes, mat1_dims.data(), 2 * sizeof(size_t));
        memcpy(matdims_bytes + 2 * sizeof(size_t), mat2_dims.data(), 2 * sizeof(size_t));
        write_all(sock, matdims_bytes, 4 * sizeof(size_t));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        vector<size_t> mat3_dims({mat1_dims[0], mat2_dims[1]});
        size_t mat3_elem_no(mat3_dims[0] * mat3_dims[1]);
        vector<Ciphertext> mat3_ct(mat3_elem_no);

        streampos inet_buf_curpos = 0;
        for (auto &c : mat3_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        vector<Plaintext> mat3_pt(mat3_elem_no);

        for (size_t i = 0; i < mat3_elem_no; ++i)
            dec.decrypt(mat3_ct[i], mat3_pt[i]);

        /*
         * Decode result
         */
        vector<vector<Complex>> mat3(mat3_elem_no, vector<Complex>(slot_no));

        for (size_t i = 0; i < mat3_elem_no; ++i)
            cencd.decode(mat3_pt[i], mat3[i]);

        /*
         * Print result
         */
        size_t slot_to_print = 0;
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < mat3_dims[0]; ++i) {
            for (size_t j = 0; j < mat3_dims[1]; ++j) {
                cout << mat3[mat3_dims[1] * i + j][slot_to_print] << "   ";
            }
            cout << '\n';
        }
        cout << ']' << '\n';
        cout << '\n';

    }

    void client_side_inv(int sock)
    {
        cout << "Running the inverse demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 30);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operand
         */
        double x = 4;

        /*
         * Encode the operand
         */
        CKKSEncoder cencd(ctx);
        Plaintext x_pt;
        cencd.encode(x, scale, x_pt);

        /*
         * Encrypt the operand
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        enc.encrypt_symmetric(x_pt).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertext to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        streampos inet_buf_curpos = 0;
        Ciphertext y_ct;
        inet_buf_curpos += y_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        cout << "Chain index: " << ctx.get_context_data(y_ct.parms_id())->chain_index() << '\n';

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        Plaintext y_pt;
        dec.decrypt(y_ct, y_pt);

        /*
         * Decode result
         */
        vector<double> y_(1);
        cencd.decode(y_pt, y_);
        double y = y_[0];

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << y;
        cout << '\n';

    }

    void client_side_inv_sqrt_twice(int sock)
    {
        cout << "Running the inverse square root demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 59, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 59 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 29);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operand
         */
        double x = -4;

        /*
         * Encode the operand
         */
        CKKSEncoder cencd(ctx);
        Plaintext x_pt;
        cencd.encode(x, scale, x_pt);

        /*
         * Encrypt the operand
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        enc.encrypt_symmetric(x_pt).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertext to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        streampos inet_buf_curpos = 0;
        Ciphertext y_ct;
        inet_buf_curpos += y_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        Plaintext y_pt;
        dec.decrypt(y_ct, y_pt);

        /*
         * Decode result
         */
        vector<double> y_(1);
        cencd.decode(y_pt, y_);
        double y = y_[0];

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << y;
        cout << '\n';

    }

    void client_side_abs(int sock)
    {
        cout << "Running the inverse square root demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 59, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 59 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 29);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operand
         */
        double x = -4;

        /*
         * Encode the operand
         */
        CKKSEncoder cencd(ctx);
        Plaintext x_pt;
        cencd.encode(x, scale, x_pt);

        /*
         * Encrypt the operand
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        enc.encrypt_symmetric(x_pt).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertext to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        streampos inet_buf_curpos = 0;
        Ciphertext y_ct;
        inet_buf_curpos += y_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        Plaintext y_pt;
        dec.decrypt(y_ct, y_pt);

        /*
         * Decode result
         */
        vector<double> y_(1);
        cencd.decode(y_pt, y_);
        double y = y_[0];

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << y;
        cout << '\n';

    }

    void client_side_twice_max(int sock)
    {
        cout << "Running the twice max demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 59, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 59 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 29);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();
        Serializable<RelinKeys> rk = kgen.create_relin_keys();

        // Save the relinearization key to output network stream
        rk.save(onet_strm);

        /*
         * Set up the operands
         */
        double x1 = -3;
        double x2 = -8;

        /*
         * Encode the operands
         */
        CKKSEncoder cencd(ctx);
        Plaintext x1_pt, x2_pt;
        cencd.encode(x1, scale, x1_pt);
        cencd.encode(x2, scale, x2_pt);

        /*
         * Encrypt the operands
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        enc.encrypt_symmetric(x1_pt).save(onet_strm);
        enc.encrypt_symmetric(x2_pt).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertext to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertext from input network buffer
        streampos inet_buf_curpos = 0;
        Ciphertext y_ct;
        inet_buf_curpos += y_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        Plaintext y_pt;
        dec.decrypt(y_ct, y_pt);

        /*
         * Decode result
         */
        vector<double> y_(1);
        cencd.decode(y_pt, y_);
        double y = y_[0];

        /*
         * Print result
         */
        cout << "Print result:" << '\n';
        cout << y;
        cout << '\n';

    }

    void client_side_fft(int sock)
    {
        cout << "Running the FFT demo." << '\n';

        /*
         * Configure parameters
         */
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 1 << 14;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 60 }));
        SEALContext ctx(parms);
        double scale = pow(2.0, 30);

        // Save the parameters to output network stream
        ostringstream onet_strm(ios::binary);
        parms.save(onet_strm);

        /*
         * Generate keys
         */
        KeyGenerator kgen(ctx);
        SecretKey sk = kgen.secret_key();

        /*
         * Set up the operand
         */
        CKKSEncoder cencd(ctx);
        size_t slot_no = cencd.slot_count();

        size_t vec_elem_no = 32; // power of 2
        vector<vector<Complex>> vec(vec_elem_no, vector<Complex>(slot_no));
        for (size_t s = 0; s < slot_no; ++s) {
            for (size_t i = 0; i < vec_elem_no; ++i)
                vec[i][s] = 2.2 * i - 10.8 * s + 513.1;
        }

        /*
         * Encode the operand
         */
        vector<Plaintext> vec_pt(vec_elem_no);
        for (size_t i = 0; i < vec_elem_no; ++i)
            cencd.encode(vec[i], scale, vec_pt[i]);

        /*
         * Encrypt the operand
         */
        // Encrypt and save the ciphertexts to output network stream
        Encryptor enc(ctx, sk);
        for (const auto &p : vec_pt)
            enc.encrypt_symmetric(p).save(onet_strm);

        /*
         * Send the parameters and the operand ciphertext to server
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write_all(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the number of elements of the operand vector
        seal_byte *vec_elem_no_bytes = reinterpret_cast<seal_byte*>(&vec_elem_no);
        write_all(sock, vec_elem_no_bytes, sizeof(vec_elem_no));

        // Send the data from the output network stream
        write_all(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        /*
         * Receive the result ciphertext from server
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the result ciphertexts
        size_t vecr_elem_no = vec_elem_no;
        vector<Ciphertext> vecr_ct(vecr_elem_no);

        streampos inet_buf_curpos = 0;
        for (auto &c : vecr_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Decrypt result
         */
        Decryptor dec(ctx, sk);
        vector<Plaintext> vecr_pt(vecr_elem_no);
        for (size_t i = 0; i < vecr_elem_no; ++i)
            dec.decrypt(vecr_ct[i], vecr_pt[i]);

        /*
         * Decode result
         */
        vector<vector<Complex>> vecr(vecr_elem_no);
        for (size_t i = 0; i < vecr_elem_no; ++i)
            cencd.decode(vecr_pt[i], vecr[i]);

        /*
         * Print result
         */
        size_t slot_to_print = 0;
        cout << "Print result:" << '\n';
        cout << '[' << '\n';
        for (size_t i = 0; i < vecr.size(); ++i) {
            cout << vecr[i][slot_to_print] << '\n';
        }
        cout << ']' << '\n';
        cout << '\n';

    }
} // namespace

void client_demo(const char **argv)
{
    int sock = setup_client();

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        client_side_##demo_name(sock); \
    else


    RUN_DEMO_IFELSE(simple)
    RUN_DEMO_IFELSE(batch_matmul)
    RUN_DEMO_IFELSE(inv)
    RUN_DEMO_IFELSE(inv_sqrt_twice)
    //RUN_DEMO_IFELSE(inv_sqrt)
    RUN_DEMO_IFELSE(abs)
    RUN_DEMO_IFELSE(twice_max)
    RUN_DEMO_IFELSE(fft)
        cout << "No such demo for " << argv[1] << "." << '\n';


    close(sock);

    cout << "Bye!" << '\n';
}
