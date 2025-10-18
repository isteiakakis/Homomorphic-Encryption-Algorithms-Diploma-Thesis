#include "he_fft.h"
#include "he_operators.h"
#include "seal/seal.h"
#include <complex>

using namespace std;
using namespace seal;
using namespace he::operators;
using Complex = complex<double>;

namespace he::fft
{
    template <int w_powr_coeff>
    static vector<Ciphertext> fft_(const CKKSEncoder &cencd, const Evaluator &eval, const vector<Ciphertext> &vec_ct)
    {
        // vec_ct = P ~ [p_0, p_1, ..., p_{n-1}] coefficient representation
        size_t n = vec_ct.size();
        if (n == 1)
            return vec_ct;

        // Split vec_ct = P into vec_ct_e = P_e (even indices) and vec_ct_o = P_o (odd indices)
        vector<Ciphertext> vec_ct_e(n/2);
        vector<Ciphertext> vec_ct_o(n/2);
        for (size_t i = 0; i < n/2; ++i) {
            vec_ct_e[i] = vec_ct[2*i];
            vec_ct_o[i] = vec_ct[2*i+1];
        }

        // Recursively compute FFT for P_e and P_o
        vector<Ciphertext> vecr_ct_e(fft_<w_powr_coeff>(cencd, eval, vec_ct_e));
        vector<Ciphertext> vecr_ct_o(fft_<w_powr_coeff>(cencd, eval, vec_ct_o));

        // Get the scale
        double cur_scale = vecr_ct_e[0].scale();

        // Get the encryption parameters
        parms_id_type cur_parms_id = vecr_ct_e[0].parms_id();

        // Compute w
        Complex w = exp(Complex(0, w_powr_coeff * -2 * M_PI / n));

        // Initialize the result array
        vector<Ciphertext> vecr_ct(n);

        // Multiplication identity plaintext
        Plaintext one_pt;
        cencd.encode(Complex(1, 0), cur_parms_id, cur_scale, one_pt);

        // Intermediate results
        Plaintext w_k_pt;
        Ciphertext tmp_ct;

        // Combine the results
        for (size_t k = 0; k < n/2; ++k) {
            cencd.encode(pow(w, k), cur_parms_id, cur_scale, w_k_pt);

            tmp_ct = eval% vecr_ct_o[k] * w_k_pt;
            tmp_ct ^= eval; // rescale

            vecr_ct_e[k] *= eval% one_pt;
            vecr_ct_e[k] ^= eval; // rescale

            vecr_ct[k] = eval% vecr_ct_e[k] + tmp_ct;
            vecr_ct[n/2+k] = eval% vecr_ct_e[k] - tmp_ct;
        }

        return vecr_ct;
    }

    vector<Ciphertext> fft(const CKKSEncoder &cencd, const Evaluator &eval, const vector<Ciphertext> &vec_ct)
    {
        return fft_<1>(cencd, eval, vec_ct);
    }

    vector<Ciphertext> ifft(const CKKSEncoder &cencd, const Evaluator &eval, const vector<Ciphertext> &vec_ct)
    {
        vector<Ciphertext> retval(fft_<-1>(cencd, eval, vec_ct));
        double n = static_cast<double>(vec_ct.size());
        Plaintext n_inv_pt;
        cencd.encode(1.0/n, retval[0].parms_id(), retval[0].scale(), n_inv_pt);
        for (auto &r : retval) {
            r *= eval% n_inv_pt;
            r ^= eval; // rescale
        }

        return retval;
    }

    template<int w_powr_coeff>
    static Plaintext diag_D(const CKKSEncoder &cencd, int d, int k, int n, const Ciphertext &ct)
    {
        Complex w = exp(Complex(0, w_powr_coeff * -2 * M_PI / (n/k*2)));
        vector<Complex> diag;
        diag.reserve(n);

        if (d == 0) {
            vector<Complex> ones(n/k, 1);

            vector<Complex> w_pows;
            w_pows.reserve(n/k);
            for (size_t i = 0; i < w_pows.capacity(); ++i)
                w_pows.push_back(- pow(w, i));

            for (size_t _ = 0; _ < k/2; ++_) {
                diag.insert(diag.end(), ones.begin(), ones.end());
                diag.insert(diag.end(), w_pows.begin(), w_pows.end());
            }
        }
        else if (d == 1) {
            vector<Complex> ones(n/k, 1);
            vector<Complex> zeros(n/k, 0);

            for (size_t _ = 0; _ < k/2 - 1; ++_) {
                diag.insert(diag.end(), ones.begin(), ones.end());
                diag.insert(diag.end(), zeros.begin(), zeros.end());
            }
            diag.insert(diag.end(), ones.begin(), ones.end());

            if (k == 2) {
                vector<Complex> w_pows;
                w_pows.reserve(n/k);
                for (size_t i = 0; i < w_pows.capacity(); ++i)
                    w_pows.push_back(pow(w, i));

                diag.insert(diag.end(), w_pows.begin(), w_pows.end());
            } else {
                diag.insert(diag.end(), zeros.begin(), zeros.end());
            }
        }
        else if (d == 2) {
            vector<Complex> zeros(n/k, 0);

            vector<Complex> w_pows;
            w_pows.reserve(n/k);
            for (size_t i = 0; i < w_pows.capacity(); ++i)
                w_pows.push_back(pow(w, i));

            if (k == 2) {
                cout << "not gonna happen" << '\n';
                return {};
            } else {
                diag.insert(diag.end(), zeros.begin(), zeros.end());
            }

            for (size_t _ = 0; _ < k/2 - 1; ++_) {
                diag.insert(diag.end(), w_pows.begin(), w_pows.end());
                diag.insert(diag.end(), zeros.begin(), zeros.end());
            }
            diag.insert(diag.end(), w_pows.begin(), w_pows.end());
        } else {
            cout << "not accepted value for d" << '\n';
            return {};
        }

        vector<Complex> diag_rep;
        diag_rep.reserve(cencd.slot_count());
        for (size_t i = 0; i < diag_rep.capacity()/diag.size(); ++i)
            diag_rep.insert(diag_rep.end(), diag.begin(), diag.end());

        Plaintext retval;
        cencd.encode(diag_rep, ct.parms_id(), ct.scale(), retval);

        return retval;
    }

    template<int w_powr_coeff>
    static Ciphertext bfft_(const CKKSEncoder &cencd, const Evaluator &eval, const GaloisKeys &gk, const Ciphertext &x_ct, size_t n)
    {
        Ciphertext y_ct(x_ct);
        Ciphertext y0_ct;
        Ciphertext y1_ct;
        Ciphertext y2_ct;
        Plaintext d_pt;

        int steps;
        int two_to_i;

        for (size_t i = 1; i < log2(n) + 1; ++i) {
            two_to_i = 1 << i;

            d_pt = diag_D<w_powr_coeff>(cencd, 0, two_to_i, n, y_ct);
            y0_ct = eval% y_ct * d_pt;
            y0_ct ^= eval; // rescale

            steps = static_cast<int>(n) / two_to_i;

            y1_ct = eval% gk% y_ct << steps;
            d_pt = diag_D<w_powr_coeff>(cencd, 1, two_to_i, n, y1_ct);
            y1_ct *= eval% d_pt;
            y1_ct ^= eval; // rescale

            if (i != 1) {
                y2_ct = eval% gk% y_ct >> steps;
                d_pt = diag_D<w_powr_coeff>(cencd, 2, two_to_i, n, y2_ct);
                y2_ct *= eval% d_pt;
                y2_ct ^= eval; // rescale

                y_ct = eval% y0_ct + y1_ct;
                y_ct += eval% y2_ct;
            } else {
                y_ct = eval% y0_ct + y1_ct;
            }
        }

        return y_ct;
    }

    Ciphertext bfft(const CKKSEncoder &cencd, const Evaluator &eval, const GaloisKeys &gk, const Ciphertext &x_ct, size_t n)
    {
        return bfft_<1>(cencd, eval, gk, x_ct, n);
    }

    Ciphertext ibfft(const CKKSEncoder &cencd, const Evaluator &eval, const GaloisKeys &gk, const Ciphertext &x_ct, size_t n)
    {
        Ciphertext retval( bfft_<-1>(cencd, eval, gk, x_ct, n));
        Plaintext n_inv_pt;
        cencd.encode(1.0/n, retval.parms_id(), retval.scale(), n_inv_pt);

        retval *= eval% n_inv_pt;
        retval ^= eval; // rescale

        return retval;
    }
} // namespace he::fft
