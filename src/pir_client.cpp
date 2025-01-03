#include "pir_client.hpp"
#include "long_fuse_filter.hpp"
#include "murmur_hash.hpp"
#include "pir.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <seal/publickey.h>
#include <vector>

using namespace std;
using namespace seal;
using namespace seal::util;

PIRClient::PIRClient(const EncryptionParameters &enc_params,
                     const PirParams &pir_params)
    : enc_params_(enc_params), pir_params_(pir_params) {

  context_ = make_shared<SEALContext>(enc_params, true);

  keygen_ = make_unique<KeyGenerator>(*context_);

  // PublicKey public_key;
  keygen_->create_public_key(public_key_);
  SecretKey secret_key = keygen_->secret_key();

  if (pir_params_.enable_symmetric) {
    encryptor_ = make_unique<Encryptor>(*context_, secret_key);
  } else {
    encryptor_ = make_unique<Encryptor>(*context_, public_key_);
  }

  decryptor_ = make_unique<Decryptor>(*context_, secret_key);
  evaluator_ = make_unique<Evaluator>(*context_);
  // encoder_ = make_unique<mEncoder>(*context_);

  // indices_.resize(pir_params_.bf_params.optimal_parameters.number_of_hashes);
}

void PIRClient::set_seed(vector<uint64_t> seed) { seed_ = std::move(seed); }

PublicKey PIRClient::get_public_key() { return public_key_; }

// int PIRClient::generate_serialized_query(uint64_t desiredIndex,
//                                          std::stringstream &stream) {

//   int N = enc_params_.poly_modulus_degree();
//   int output_size = 0;
//   indices_ = compute_indices(desiredIndex, pir_params_.nvec);
//   Plaintext pt(enc_params_.poly_modulus_degree());

//   for (uint32_t i = 0; i < indices_.size(); i++) {
//     uint32_t num_ptxts = ceil((pir_params_.nvec[i] + 0.0) / N);
//     // initialize result.
//     cout << "Client: index " << i + 1 << "/ " << indices_.size() << " = "
//          << indices_[i] << endl;
//     cout << "Client: number of ctxts needed for query = " << num_ptxts <<
//     endl;

//     for (uint32_t j = 0; j < num_ptxts; j++) {
//       pt.set_zero();
//       if (indices_[i] >= N * j && indices_[i] <= N * (j + 1)) {
//         uint64_t real_index = indices_[i] - N * j;
//         uint64_t n_i = pir_params_.nvec[i];
//         uint64_t total = N;
//         if (j == num_ptxts - 1) {
//           total = n_i % N;
//         }
//         uint64_t log_total = ceil(log2(total));

//         cout << "Client: Inverting " << pow(2, log_total) << endl;
//         pt[real_index] =
//             invert_mod(pow(2, log_total), enc_params_.plain_modulus());
//       }

//       if (pir_params_.enable_symmetric) {
//         output_size += encryptor_->encrypt_symmetric(pt).save(stream);
//       } else {
//         output_size += encryptor_->encrypt(pt).save(stream);
//       }
//     }
//   }

//   return output_size;
// }

PirQuery PIRClient::generate_bf_query(uint64_t desiredKey) {
  uint64_t N = enc_params_.poly_modulus_degree();
  uint64_t bf_filter_num = 1;
  vector<uint64_t> tmp_nvec(pir_params_.bf_d - 1);
  for (uint32_t i = 1; i < pir_params_.bf_d; i++) {
    bf_filter_num *= pir_params_.bf_nvec[i];
    tmp_nvec[i - 1] = pir_params_.bf_nvec[i];
  }

  uint64_t bf_partition_seed = seed_[0];
  uint32_t filter_idx = murmurhash(reinterpret_cast<const char *>(&desiredKey),
                                   sizeof(desiredKey), bf_partition_seed);
  filter_idx %= bf_filter_num;

  bloom_parameters bf_params = pir_params_.bf_params;
  bloom_filter bf(bf_params);
  // bfIndices.first就是对应明文的序号
  vector<pair<uint64_t, uint64_t>> bfIndices = bf.get_indices(desiredKey);
  uint64_t bf_hash_num = bf_params.optimal_parameters.number_of_hashes;

  vector<vector<uint64_t>> indices;
  indices.resize(pir_params_.bf_d);
  indices[0].resize(bf_hash_num);
  for (uint64_t i = 0; i < bf_hash_num; ++i) {
    indices[0][i] = bfIndices[i].first;
  }
  vector<uint64_t> tmp_indices = compute_indices(filter_idx, tmp_nvec);
  for (uint64_t i = 1; i < pir_params_.bf_d; ++i) {
    indices[i].push_back(tmp_indices[i - 1]);
  }

  PirQuery result(pir_params_.bf_d);
  for (uint32_t i = 0; i < pir_params_.bf_d; i++) {
    Plaintext pt(N);

    // 如果当前维度的明文数大于N，也就是一个明文放不下当前维度的query
    // 需要num_ptxts个明文
    uint64_t n_i = pir_params_.bf_nvec[i];
    printf("i: %u, ni: %lu\n", i, n_i);
    uint32_t num_ptxts = ceil((n_i + 0.0) / N);

    for (uint32_t j = 0; j < num_ptxts; j++) {
      pt.set_zero();

      uint64_t total = N;
      if (j == num_ptxts - 1) {
        total = n_i % N;
      }
      uint64_t log_total = ceil(log2(total));

      // 处理h_i(x)
      for (uint32_t idx = 0; idx < indices[i].size(); ++idx) {
        // *****************************************似乎是下面这两行报过数组越界？
        if (indices[i][idx] >= N * j && indices[i][idx] <= N * (j + 1)) {
          uint64_t real_index = indices[i][idx] - N * j;

          cout << "Client: Inverting " << pow(2, log_total) << endl;
          pt[real_index] =
              invert_mod(pow(2, log_total), enc_params_.plain_modulus());
        }
      }

      Ciphertext dest;
      if (pir_params_.enable_symmetric) {
        encryptor_->encrypt_symmetric(pt, dest);
      } else {
        encryptor_->encrypt(pt, dest);
      }
      result[i].push_back(dest);
    }
  }

  return result;
}

PirQuery PIRClient::generate_lff_query(uint64_t desiredKey) {
  uint64_t lff_filter_num = 1;
  vector<uint64_t> tmp_nvec(pir_params_.lff_d - 1);
  for (uint32_t i = 1; i < pir_params_.lff_d; i++) {
    lff_filter_num *= pir_params_.lff_nvec[i];
    tmp_nvec[i - 1] = pir_params_.lff_nvec[i];
  }

  uint64_t lff_partition_seed = seed_[1];
  uint32_t filter_idx = murmurhash(reinterpret_cast<const char *>(&desiredKey),
                                   sizeof(desiredKey), lff_partition_seed);
  filter_idx %= lff_filter_num;

  long_fuse_params params = pir_params_.lff_params;
  uint64_t hash = long_fuse_mix_split(desiredKey, seed_[filter_idx + 1]);
  long_hashes_t hashes = long_fuse_hash_batch(hash, params);
  vector<uint64_t> lff_indices({hashes.h0, hashes.h1, hashes.h2});
  // printf("h0: %u, h1: %u, h2: %u\n", hashes.h0, hashes.h1, hashes.h2);
  assert(lff_indices.size() == lff_hash_num);

  vector<vector<uint64_t>> indices;
  indices.resize(pir_params_.lff_d);
  indices[0].resize(lff_hash_num);
  indices[0][0] = hashes.h0;
  indices[0][1] = hashes.h1;
  indices[0][2] = hashes.h2;
  vector<uint64_t> tmp_indices = compute_indices(filter_idx, tmp_nvec);
  for (uint64_t i = 1; i < pir_params_.lff_d; ++i) {
    indices[i].push_back(tmp_indices[i - 1]);
  }

  PirQuery result(pir_params_.lff_d);
  uint64_t N = enc_params_.poly_modulus_degree();

  // 处理每个维度
  for (uint32_t i = 0; i < pir_params_.lff_d; i++) {
    Plaintext pt(enc_params_.poly_modulus_degree());

    // 如果当前维度的明文数大于N，也就是一个明文放不下当前维度的query
    // 需要num_ptxts个明文
    uint64_t n_i = pir_params_.lff_nvec[i];
    printf("i: %u, ni: %lu\n", i, n_i);
    uint32_t num_ptxts = ceil((n_i + 0.0) / N);

    for (uint32_t j = 0; j < num_ptxts; j++) {
      pt.set_zero();

      uint64_t total = N;
      if (j == num_ptxts - 1) {
        total = n_i % N;
      }
      uint64_t log_total = ceil(log2(total));

      // 处理h_i(x)
      for (uint32_t idx = 0; idx < indices[i].size(); ++idx) {
        // *****************************************似乎是下面这两行报过数组越界？
        if (indices[i][idx] >= N * j && indices[i][idx] <= N * (j + 1)) {
          uint64_t real_index = indices[i][idx] - N * j;

          cout << "Client: Inverting " << pow(2, log_total) << endl;
          pt[real_index] =
              invert_mod(pow(2, log_total), enc_params_.plain_modulus());
        }
      }

      Ciphertext dest;
      if (pir_params_.enable_symmetric) {
        encryptor_->encrypt_symmetric(pt, dest);
      } else {
        encryptor_->encrypt(pt, dest);
      }
      result[i].push_back(dest);
    }
  }

  return result;
}

uint64_t PIRClient::get_fv_index(uint64_t element_index) {
  return static_cast<uint64_t>(element_index /
                               pir_params_.elements_per_plaintext);
}

uint64_t PIRClient::get_fv_offset(uint64_t element_index) {
  return element_index % pir_params_.elements_per_plaintext;
}

Plaintext PIRClient::decrypt(Ciphertext ct) const {
  Plaintext pt;
  decryptor_->decrypt(ct, pt);
  return pt;
}

uint64_t PIRClient::decode_bf_reply(const Ciphertext &reply) {
  // uint64_t PIRClient::decode_bf_reply(PirReply &reply) {
  Plaintext result = decode_reply(reply, bf_id);
  return result[0];
  // return extract_bf_bytes(result);
}

uint64_t PIRClient::decode_lff_reply(const Ciphertext &reply) {
  Plaintext result = decode_reply(reply, lff_id);
  return result[0];
  // return extract_lff_bytes(result);
}

// vector<uint64_t> PIRClient::extract_coeffs(Plaintext pt) {
//   vector<uint64_t> coeffs;
//   encoder_->decode(pt, coeffs);
//   return coeffs;
// }

// std::vector<uint64_t> PIRClient::extract_coeffs(seal::Plaintext pt,
//                                                 uint64_t offset) {
//   vector<uint64_t> coeffs;
//   encoder_->decode(pt, coeffs);

//   uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));

//   uint64_t coeffs_per_element =
//       coefficients_per_element(logt, pir_params_.ele_size);

//   return std::vector<uint64_t>(coeffs.begin() + offset * coeffs_per_element,
//                                coeffs.begin() +
//                                    (offset + 1) * coeffs_per_element);
// }

uint64_t PIRClient::extract_bf_bytes(seal::Plaintext pt) {
  uint32_t N = enc_params_.poly_modulus_degree();
  uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));
  uint32_t bytes_per_ptxt = 1;

  // Convert from FV plaintext (polynomial) to database element at the client
  vector<uint8_t> elems(bytes_per_ptxt);
  vector<uint64_t> coeffs;
  coeffs.resize(N);
  for (uint64_t i = 0; i < N; ++i) {
    coeffs[i] = pt[i];
  }
  // encoder_->decode(pt, coeffs);
  printf("coeffs0: %lu\n", coeffs[0]);
  return coeffs[0];
}

std::vector<uint8_t> PIRClient::extract_lff_bytes(seal::Plaintext pt) {
  uint32_t N = enc_params_.poly_modulus_degree();
  uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));

  // Convert from FV plaintext (polynomial) to database element at the client
  vector<uint8_t> elems(pir_params_.ele_size);
  vector<uint64_t> coeffs(N);
  for (uint64_t i = 0; i < N; ++i) {
    coeffs[i] = pt[i];
  }
  coeffs_to_bytes(logt, coeffs, elems.data(), pir_params_.ele_size,
                  pir_params_.ele_size);
  return elems;
}

Plaintext PIRClient::decode_reply(const Ciphertext &reply, uint8_t db_id) {
  Plaintext res;
  decryptor_->decrypt(reply, res);
  return res;
}

// Plaintext PIRClient::decode_reply(PirReply &reply, uint8_t db_id) {
//   EncryptionParameters parms;
//   parms_id_type parms_id;
//   if (pir_params_.enable_mswitching) {
//     parms = context_->last_context_data()->parms();
//     parms_id = context_->last_parms_id();
//   } else {
//     parms = context_->first_context_data()->parms();
//     parms_id = context_->first_parms_id();
//   }
//   uint32_t exp_ratio = compute_expansion_ratio(parms);
//   uint32_t recursion_level;
//   if (db_id == bf_id) {
//     recursion_level = pir_params_.bf_d;
//   } else {
//     recursion_level = pir_params_.lff_d;
//   }

//   vector<Ciphertext> temp = reply;
//   uint32_t ciphertext_size = temp[0].size();

//   uint64_t t = enc_params_.plain_modulus().value();

//   for (uint32_t i = 0; i < recursion_level; i++) {
//     cout << "Client: " << i + 1 << "/ " << recursion_level
//          << "-th decryption layer started." << endl;
//     vector<Ciphertext> newtemp;
//     vector<Plaintext> tempplain;

//     for (uint32_t j = 0; j < temp.size(); j++) {
//       Plaintext ptxt;
//       decryptor_->decrypt(temp[j], ptxt);
// #ifdef DEBUG
//       cout << "Client: reply noise budget = "
//            << decryptor_->invariant_noise_budget(temp[j]) << endl;
// #endif

//       // cout << "decoded (and scaled) plaintext = " << ptxt.to_string() <<
//       // endl;
//       tempplain.push_back(ptxt);

// #ifdef DEBUG
//       cout << "recursion level : " << i << " noise budget :  ";
//       cout << decryptor_->invariant_noise_budget(temp[j]) << endl;
// #endif

//       if ((j + 1) % (exp_ratio * ciphertext_size) == 0 && j > 0) {
//         // Combine into one ciphertext.
//         Ciphertext combined(*context_, parms_id);
//         compose_to_ciphertext(parms, tempplain, combined);
//         newtemp.push_back(combined);
//         tempplain.clear();
//         // cout << "Client: const term of ciphertext = " << combined[0] <<
//         endl;
//       }
//     }
//     cout << "Client: done." << endl;
//     cout << endl;
//     if (i == recursion_level - 1) {
//       assert(temp.size() == 1);
//       return tempplain[0];
//     } else {
//       tempplain.clear();
//       temp = newtemp;
//     }
//   }

//   // This should never be called
//   assert(0);
//   Plaintext fail;
//   return fail;
// }

GaloisKeys PIRClient::generate_galois_keys() {
  // Generate the Galois keys needed for coeff_select.
  vector<uint32_t> galois_elts;
  int N = enc_params_.poly_modulus_degree();
  int logN = get_power_of_two(N);

  // cout << "printing galois elements...";
  for (int i = 0; i < logN; i++) {
    galois_elts.push_back((N + exponentiate_uint(2, i)) /
                          exponentiate_uint(2, i));
    //#ifdef DEBUG
    // cout << galois_elts.back() << ", ";
    //#endif
  }
  GaloisKeys gal_keys;
  keygen_->create_galois_keys(galois_elts, gal_keys);
  return gal_keys;
}

// Plaintext PIRClient::replace_element(Plaintext pt, vector<uint64_t>
// new_element,
//                                      uint64_t offset) {
//   vector<uint64_t> coeffs = extract_coeffs(pt);

//   uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));
//   uint64_t coeffs_per_element =
//       coefficients_per_element(logt, pir_params_.ele_size);

//   assert(new_element.size() == coeffs_per_element);

//   for (uint64_t i = 0; i < coeffs_per_element; i++) {
//     coeffs[i + offset * coeffs_per_element] = new_element[i];
//   }

//   Plaintext new_pt;

//   for (uint64_t i = 0; i < )
//   encoder_->encode(coeffs, new_pt);
//   return new_pt;
// }

Ciphertext PIRClient::get_one() {
  Plaintext pt("1");
  Ciphertext ct;
  if (pir_params_.enable_symmetric) {
    encryptor_->encrypt_symmetric(pt, ct);
  } else {
    encryptor_->encrypt(pt, ct);
  }
  return ct;
}
