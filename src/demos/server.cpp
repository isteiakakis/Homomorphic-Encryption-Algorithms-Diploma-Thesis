#include "he_fft.h"
#include "he_math.h"
#include "he_linalg.h"
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
using namespace he::operators;
using namespace he::math;
using namespace he::fft;
using namespace he::linalg;
using Complex = complex<double>;

/* Server */

namespace
{
    int setup_server()
    {
        const char ip_addr[] = "127.0.0.1";
        int init_port = 8080;
        int fin_port = init_port + 20;
        int server_fd;

        // Create socket file descriptor
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("Socket failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in address;
        address.sin_family = AF_INET;

        // Convert IPv4 and IPv6 addresses from text to binary form
        if (inet_pton(AF_INET, ip_addr, &address.sin_addr) <= 0) {
            perror("Invalid address / Address not supported");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Scan the port range in order to bind
        int port;
        for (port = init_port; port <= fin_port; ++port) {
            // Bind the socket to the network address and port
            address.sin_port = htons(port);

            // Binding the socket to the port
            if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == 0)
                goto bind_success;
        }

        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);

bind_success:

        // Listen for incoming connections
        if (listen(server_fd, 1) < 0) {
            perror("Listen");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        cout << "Waiting for connection on " << ip_addr << ":" << port << '\n';

        // Accept an incoming connection
        int new_socket;
        if ((new_socket = accept(server_fd, nullptr, nullptr)) < 0) {
            perror("Accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Close the listening socket
        close(server_fd);

        cout << "Connection established." << "\n\n";

        return new_socket;
    }

    void server_side_simple(int sock)
    {
        cout << "Running the simple demo." << '\n';

        /*
         * Receive the parameters and the operand ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        Ciphertext op1_ct, op2_ct;
        inet_buf_curpos += op1_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        inet_buf_curpos += op2_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        Evaluator eval(ctx);
        Ciphertext res_ct;

        res_ct = eval% op1_ct * op2_ct;

        res_ct &= eval% rk; // relin
        res_ct ^= eval; // rescale

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        res_ct.save(onet_strm);

        /*
         * Send the result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    void server_side_batch_matmul(int sock)
    {
        cout << "Running the batch matrix multiplication demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the dimensions of the operand matrices
        seal_byte matdims_bytes[4 * sizeof(size_t)];
        read_all(sock, matdims_bytes, 4 * sizeof(size_t));
        vector<size_t> mat1_dims(2), mat2_dims(2);
        memcpy(mat1_dims.data(), matdims_bytes, 2 * sizeof(size_t));
        memcpy(mat2_dims.data(), matdims_bytes + 2 * sizeof(size_t), 2 * sizeof(size_t));

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        size_t mat1_elem_no = mat1_dims[0] * mat1_dims[1];
        size_t mat2_elem_no = mat2_dims[0] * mat2_dims[1];

        vector<Ciphertext> mat1_elems_ct(mat1_elem_no);
        vector<Ciphertext> mat2_elems_ct(mat2_elem_no);

        for (auto &c : mat1_elems_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        for (auto &c : mat2_elems_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        Evaluator eval(ctx);

        Matrix mat1_ct(mat1_dims[0], mat1_dims[1], mat1_elems_ct);
        Matrix mat2_ct(mat2_dims[0], mat2_dims[1], mat2_elems_ct);

        Matrix mat3_ct = mat1_ct.matmul(eval, rk, mat2_ct);

        vector<Ciphertext> mat3_elems_ct = mat3_ct.get_elems();

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        for (const auto &c : mat3_elems_ct)
            c.save(onet_strm);

        /*
         * Send result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    // f(x) = x^(-1) = 1/x
    void server_side_inv(int sock)
    {
        cout << "Running the inverse demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        Ciphertext x_ct;

        inet_buf_curpos += x_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        Ciphertext y_ct = signed_inv(cencd, eval, rk, x_ct, 0.01, 7);

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        y_ct.save(onet_strm);

        /*
         * Send result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    // f(x) = (2x)^(-1/2) = 1/sqrt(2x)
    void server_side_inv_sqrt_twice(int sock)
    {
        cout << "Running the inverse square root demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        Ciphertext x_ct;

        inet_buf_curpos += x_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        Ciphertext y_ct = signed_inv(cencd, eval, rk, x_ct, 0.01, 4);

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        y_ct.save(onet_strm);

        /*
         * Send result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    void server_side_abs(int sock)
    {
        cout << "Running the abs demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        Ciphertext x_ct;

        inet_buf_curpos += x_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        Ciphertext y_ct = abs(ctx, cencd, eval, rk, x_ct, 0.1, 4);

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        y_ct.save(onet_strm);

        /*
         * Send result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    void server_side_twice_max(int sock)
    {
        cout << "Running the twice max demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the relinearization key from input network buffer
        RelinKeys rk;
        inet_buf_curpos += rk.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Load the operand ciphertexts from input network buffer
        Ciphertext x1_ct, x2_ct;

        inet_buf_curpos += x1_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        inet_buf_curpos += x2_ct.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;
        inet_buf_curpos = 0;

        /*
         * Perform encrypted computation
         */
        CKKSEncoder cencd(ctx);
        Evaluator eval(ctx);

        Ciphertext x_diff_ct = eval% x1_ct - x2_ct;
        Ciphertext x_abs_diff_ct = abs(ctx, cencd, eval, rk, x_diff_ct, 0.1, 4);

        Ciphertext x_sum_ct = eval% x1_ct + x2_ct;

        // Rescale x_sum to reach x_abs_diff
        size_t num_of_rescales = ctx.get_context_data(x_sum_ct.parms_id())->chain_index() - ctx.get_context_data(x_abs_diff_ct.parms_id())->chain_index();
        Plaintext one_pt;
        for (size_t i = 0; i < num_of_rescales; ++i) {
            cencd.encode(1, x_sum_ct.parms_id(), x_sum_ct.scale(), one_pt);
            x_sum_ct *= eval% one_pt;
            x_sum_ct ^= eval; // rescale
        }

        Ciphertext y_ct = eval% x_abs_diff_ct + x_sum_ct;

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        y_ct.save(onet_strm);

        /*
         * Send result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

    void server_side_fft(int sock)
    {
        cout << "Running the FFT demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the number of elements of the operand vector
        size_t vec_elem_no;
        seal_byte vec_elem_no_bytes[sizeof(vec_elem_no)];
        read_all(sock, vec_elem_no_bytes, sizeof(vec_elem_no));
        vec_elem_no = *reinterpret_cast<size_t*>(vec_elem_no_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the operand ciphertexts from input network buffer
        vector<Ciphertext> vec_ct(vec_elem_no);
        for (auto &c : vec_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Perform encrypted computation
         */
        Evaluator eval(ctx);
        CKKSEncoder cencd(ctx);
        vector<Ciphertext> vecr_ct = fft(cencd, eval, vec_ct);

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        for (const auto &c : vecr_ct)
            c.save(onet_strm);

        /*
         * Send the result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }

#if 0
    // TODO
    void server_side_bfft_filter(int sock)
    {
        cout << "Running the BFFT filter demo." << '\n';

        /*
         * Receive parameters and ciphertexts from client
         */
        // Receive the size of the received data (aka the size of the input network buffer)
        streampos inet_buf_sz;
        seal_byte inet_buf_sz_bytes[sizeof(inet_buf_sz)];
        read_all(sock, inet_buf_sz_bytes, sizeof(inet_buf_sz));
        inet_buf_sz = *reinterpret_cast<streampos*>(inet_buf_sz_bytes);

        // Receive the number of elements of the operand vector
        size_t vec_elem_no;
        seal_byte vec_elem_no_bytes[sizeof(vec_elem_no)];
        read_all(sock, vec_elem_no_bytes, sizeof(vec_elem_no));
        vec_elem_no = *reinterpret_cast<size_t*>(vec_elem_no_bytes);

        // Receive the data to input network buffer
        seal_byte *inet_buf = new seal_byte[inet_buf_sz];
        read_all(sock, inet_buf, inet_buf_sz);

        // Load the parameters from input network buffer
        EncryptionParameters parms;
        streampos inet_buf_curpos = 0;
        inet_buf_curpos += parms.load(inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);
        SEALContext ctx(parms);

        // Load the operand ciphertexts from input network buffer
        vector<Ciphertext> vec_ct(vec_elem_no);
        for (auto &c : vec_ct)
            inet_buf_curpos += c.load(ctx, inet_buf + inet_buf_curpos, inet_buf_sz - inet_buf_curpos);

        // Empty input network buffer
        delete[] inet_buf;

        /*
         * Perform encrypted computation
         */
        Evaluator eval(ctx);
        CKKSEncoder cencd(ctx);
        vector<Ciphertext> vecr_ct = fft(cencd, eval, vec_ct);

        // Save the result ciphertext to output network stream
        ostringstream onet_strm(ios::binary);
        for (const auto &c : vecr_ct)
            c.save(onet_strm);

        /*
         * Send the result ciphertext to client
         */
        // Send the size of the sending data
        streampos onet_strm_sz = onet_strm.tellp();
        seal_byte *onet_strm_sz_bytes = reinterpret_cast<seal_byte*>(&onet_strm_sz);
        write(sock, onet_strm_sz_bytes, sizeof(onet_strm_sz));

        // Send the data from the output network stream
        write(sock, onet_strm.str().data(), onet_strm_sz);

        // Empty output network stream
        onet_strm.str("");

        cout << '\n';

    }
#endif
} // namespace

void server_demo(const char **argv)
{
    int sock = setup_server();

#define RUN_DEMO_IFELSE(demo_name) \
    if (argv[2] == #demo_name##sv) \
        server_side_##demo_name(sock); \
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
