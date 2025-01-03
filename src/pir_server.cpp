#include "pir_server.hpp"
#include "bloom_filter.hpp"
#include "long_fuse_filter.hpp"
#include "murmur_hash.hpp"
#include "pir.hpp"
#include "pir_client.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <sys/types.h>
#include <utility>
#include <vector>

using namespace std;
using namespace seal;
using namespace seal::util;

PIRServer::PIRServer(const EncryptionParameters &enc_params,
                     const PirParams &pir_params,
                     const seal::PublicKey &public_key, const PIRClient &client)
    : client_(client), enc_params_(enc_params), pir_params_(pir_params),
      is_db_preprocessed_(false) {
  context_ = make_shared<SEALContext>(enc_params, true);
  evaluator_ = make_unique<Evaluator>(*context_);
  encryptor_ = make_unique<Encryptor>(*context_, public_key);
}

void PIRServer::preprocess_database() {
  if (!is_db_preprocessed_) {

    for (uint32_t i = 0; i < bf_db_->size(); i++) {
      evaluator_->transform_to_ntt_inplace(bf_db_->operator[](i),
                                           context_->first_parms_id());
    }
    for (uint32_t i = 0; i < lff_db_->size(); i++) {
      evaluator_->transform_to_ntt_inplace(lff_db_->operator[](i),
                                           context_->first_parms_id());
    }

    is_db_preprocessed_ = true;
  }
}

// Server takes over ownership of db and will free it when it exits
void PIRServer::set_database(unique_ptr<vector<Plaintext>> &&bf_db,
                             unique_ptr<vector<Plaintext>> &&lff_db) {
  if (!bf_db || !lff_db) {
    throw invalid_argument("db cannot be null");
  }

  bf_db_ = std::move(bf_db);
  lff_db_ = std::move(lff_db);
  is_db_preprocessed_ = false;
}

vector<uint64_t> PIRServer::set_database(const DBType &db_vec, uint64_t ele_num,
                                         uint64_t ele_size) {
  assert(db_vec.size() == pir_params_.ele_num);
  uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));
  uint32_t N = enc_params_.poly_modulus_degree();

  uint64_t ele_per_ptxt = pir_params_.elements_per_plaintext;
  uint64_t bytes_per_ptxt = ele_per_ptxt * ele_size;
  uint64_t db_size = ele_num * ele_size;

  uint64_t bf_prod = 1;
  for (uint32_t i = 0; i < pir_params_.bf_d; i++) {
    bf_prod *= pir_params_.bf_nvec[i];
  }
  uint64_t lff_prod = 1;
  for (uint32_t i = 0; i < pir_params_.lff_d; i++) {
    lff_prod *= pir_params_.lff_nvec[i];
  }

  /*********************************************************************
  encode bloom filter
  *********************************************************************/
  uint64_t bf_filter_num = 1;
  for (uint32_t i = 1; i < pir_params_.bf_d; i++) {
    bf_filter_num *= pir_params_.bf_nvec[i];
  }
  bloom_parameters bf_params = pir_params_.bf_params;
  uint64_t bf_number_of_hashes = bf_params.optimal_parameters.number_of_hashes;

  vector<bloom_filter> bf;
  bf.reserve(bf_filter_num);
  for (uint64_t i = 0; i < bf_filter_num; ++i) {
    bloom_filter tmp_bf(bf_params);
    bf.emplace_back(std::move(tmp_bf));
  }

  /***************
  generate sub vectors
  ***************/
  vector<vector<uint64_t>> bf_sub_vectors(bf_filter_num);
  for (uint64_t i = 0; i < bf_filter_num; ++i) {
    bf_sub_vectors[i].reserve(pir_params_.max_bf_filter_size);
  }

  seal::Blake2xbPRNGFactory factory;
  auto gen = factory.create();
  uint32_t bf_partition_seed;
  bool isContinue = true;
  while (isContinue) {
    bf_partition_seed = gen->generate();
    for (uint64_t i = 0; i < ele_num; ++i) {
      uint32_t filter_idx =
          murmurhash(reinterpret_cast<const char *>(&db_vec[i].first),
                     sizeof(db_vec[i].first), bf_partition_seed);
      filter_idx %= bf_filter_num;

      bf_sub_vectors[filter_idx].emplace_back(db_vec[i].first);
    }

    isContinue = false;
    for (uint64_t i = 0; i < bf_filter_num; ++i) {
      if (bf_sub_vectors[i].size() > pir_params_.max_bf_filter_size) {
        isContinue = true;
        break;
      }
    }
  }

  for (uint64_t i = 0; i < bf_filter_num; ++i) {
    for (uint64_t j = 0; j < bf_sub_vectors[i].size(); ++j) {
      bf[i].insert(bf_sub_vectors[i][j]);
    }
  }

  auto bf_result = make_unique<vector<Plaintext>>();
  bf_result->reserve(bf_prod);

  /***************
  encode bf database
  ***************/

  for (uint64_t i = 0; i < bf_params.optimal_parameters.table_size; ++i) {
    for (uint64_t filter_idx = 0; filter_idx < bf_filter_num; ++filter_idx) {
      vector<uint64_t> coefficients;
      coefficients.reserve(N);

      uint8_t tmp_bit = bf[filter_idx].get_bit_at(i);
      coefficients.emplace_back((uint64_t)tmp_bit);
      for (uint64_t j = 1; j < N; ++j) {
        coefficients.emplace_back(1);
      }

      Plaintext plain(N);
      vector_to_plaintext(coefficients, plain);
      bf_result->emplace_back(std::move(plain));
    }
  }

  // Add padding to make database a matrix
  uint64_t bf_current_plaintexts = bf_result->size();
  // assert(bf_current_plaintexts <= bf_num_of_plaintexts);

#ifdef DEBUG
  cout << "adding: " << matrix_plaintexts - current_plaintexts
       << " FV plaintexts of padding (equivalent to: "
       << (matrix_plaintexts - current_plaintexts) *
              elements_per_ptxt(logt, N, ele_size)
       << " elements)" << endl;
#endif

  vector<uint64_t> padding(N, 1);
  for (uint64_t i = 0; i < (bf_prod - bf_current_plaintexts); i++) {
    Plaintext plain;
    vector_to_plaintext(padding, plain);
    bf_result->emplace_back(std::move(plain));
  }

  /*********************************************************************
  encode long fuse filter
  *********************************************************************/
  uint64_t lff_filter_num = 1;
  for (uint32_t i = 1; i < pir_params_.lff_d; i++) {
    lff_filter_num *= pir_params_.lff_nvec[i];
  }
  long_fuse_params lff_params = pir_params_.lff_params;
  vector<long_fuse_t> lff(lff_filter_num);
  for (uint64_t i = 0; i < lff_filter_num; ++i) {
    long_fuse_allocate(lff_params, &lff[i]);
  }

  /***************
  generate sub key-value(long) maps
  ***************/
  vector<KVMapType> lff_sub_kv_maps(lff_filter_num);
  for (uint64_t i = 0; i < lff_filter_num; ++i) {
    lff_sub_kv_maps[i].reserve(pir_params_.max_lff_filter_size);
  }
  uint64_t lff_value_long_length = lff_params.ValueLongLength;
  assert(lff_value_long_length <= N);

  // seal::Blake2xbPRNGFactory factory;
  // auto gen = factory.create();
  uint32_t lff_partition_seed;
  isContinue = true;
  while (isContinue) {
    lff_partition_seed = gen->generate();
    for (uint64_t i = 0; i < ele_num; ++i) {
      uint32_t filter_idx =
          murmurhash(reinterpret_cast<const char *>(&db_vec[i].first),
                     sizeof(db_vec[i].first), lff_partition_seed);
      filter_idx %= lff_filter_num;

      // vector<uint64_t> coeffs =
      //     bytes_to_coeffs(logt, db_vec[i].second.data(), ele_size);
      // pair<uint64_t, vector<uint64_t>> kv_pair =
      //     make_pair(db_vec[i].first, std::move(coeffs));
      pair<uint64_t, vector<uint64_t>> kv_pair =
          make_pair(db_vec[i].first, vector<uint64_t>(1, db_vec[i].second));
      lff_sub_kv_maps[filter_idx].emplace_back(std::move(kv_pair));
    }

    isContinue = false;
    // printf("max length: %lu\n", pir_params_.max_lff_filter_size);
    for (uint64_t i = 0; i < lff_filter_num; ++i) {
      // printf("i: %lu, sub map length: %lu\n", i, lff_sub_kv_maps[i].size());
      if (lff_sub_kv_maps[i].size() > pir_params_.max_lff_filter_size) {
        isContinue = true;
        break;
      }
    }
  }

  for (uint64_t i = 0; i < lff_filter_num; ++i) {
    assert(long_fuse_populate(lff_sub_kv_maps[i], lff_sub_kv_maps[i].size(),
                              lff_value_long_length,
                              enc_params_.plain_modulus().value(), &lff[i]));
  }

  /***************
  encode lff database
  ***************/
  auto lff_result = make_unique<vector<Plaintext>>();
  lff_result->reserve(lff_prod);
  for (uint64_t i = 0; i < lff_params.ArrayLength; ++i) {
    for (uint64_t filter_idx = 0; filter_idx < lff_filter_num; ++filter_idx) {
      vector<uint64_t> coefficients(N);
      assert(lff[filter_idx].Fingerprints[i].size() == lff_value_long_length);
      memcpy(coefficients.data(), lff[filter_idx].Fingerprints[i].data(),
             lff_value_long_length * sizeof(uint64_t));

      for (uint64_t j = lff_value_long_length; j < N; ++j) {
        coefficients[j] = 1;
      }

      Plaintext plain;
      vector_to_plaintext(coefficients, plain);
      lff_result->emplace_back(std::move(plain));
    }
  }

  uint64_t lff_current_plaintexts = lff_result->size();

#ifdef DEBUG
  cout << "adding: " << matrix_plaintexts - current_plaintexts
       << " FV plaintexts of padding (equivalent to: "
       << (matrix_plaintexts - current_plaintexts) *
              elements_per_ptxt(logt, N, ele_size)
       << " elements)" << endl;
#endif

  for (uint64_t i = 0; i < (lff_prod - lff_current_plaintexts); i++) {
    Plaintext plain;
    vector_to_plaintext(padding, plain);
    lff_result->emplace_back(std::move(plain));
  }

  set_database(std::move(bf_result), std::move(lff_result));

  vector<uint64_t> seed_vec(lff_filter_num + 2);
  seed_vec[0] = bf_partition_seed;
  seed_vec[1] = lff_partition_seed;
  for (uint64_t i = 0; i < lff_filter_num; ++i) {
    seed_vec[i + 2] = lff[i].Seed;
  }
  return seed_vec;
}

void PIRServer::set_galois_key(uint32_t client_id, seal::GaloisKeys galkey) {
  galoisKeys_[client_id] = galkey;
}

// PirQuery PIRServer::deserialize_query(stringstream &stream) {
//   PirQuery q;

//   for (uint32_t i = 0; i < pir_params_.d; i++) {
//     // number of ciphertexts needed to encode the index for dimension i
//     // keeping into account that each ciphertext can encode up to
//     // poly_modulus_degree indexes In most cases this is usually 1.
//     uint32_t ctx_per_dimension = ceil((pir_params_.bf_nvec[i] + 0.0) /
//                                       enc_params_.poly_modulus_degree());

//     vector<Ciphertext> cs;
//     for (uint32_t j = 0; j < ctx_per_dimension; j++) {
//       Ciphertext c;
//       c.load(*context_, stream);
//       cs.push_back(c);
//     }

//     q.push_back(cs);
//   }

//   return q;
// }

int PIRServer::serialize_reply(PirReply &reply, stringstream &stream) {
  int output_size = 0;
  for (int i = 0; i < reply.size(); i++) {
    evaluator_->mod_switch_to_inplace(reply[i], context_->last_parms_id());
    output_size += reply[i].save(stream);
  }
  return output_size;
}

pair<Ciphertext, uint64_t>
PIRServer::generate_reply(PirQuery &query, uint32_t client_id, uint8_t db_id) {
  vector<uint64_t> nvec;
  vector<Plaintext> *cur;
  if (db_id == bf_id) {
    nvec = pir_params_.bf_nvec;
    cur = bf_db_.get();
  } else if (db_id == lff_id) {
    nvec = pir_params_.lff_nvec;
    cur = lff_db_.get();
  }
  vector<Ciphertext> intermediate_cipher;
  uint64_t product = 1;

  for (uint32_t i = 0; i < nvec.size(); i++) {
    product *= nvec[i];
  }

  auto coeff_count = enc_params_.poly_modulus_degree();

  vector<Plaintext> intermediate_plain; // decompose....

  auto pool = MemoryManager::GetPool();

  int N = enc_params_.poly_modulus_degree();

  int logt = floor(log2(enc_params_.plain_modulus().value()));

  for (uint32_t i = 0; i < nvec.size(); i++) {
    cout << "Server: " << i + 1 << "-th recursion level started " << endl;

    vector<Ciphertext> expanded_query;

    uint64_t n_i = nvec[i];
    cout << "Server: n_i = " << n_i << endl;
    cout << "Server: expanding " << query[i].size() << " query ctxts" << endl;
    for (uint32_t j = 0; j < query[i].size(); j++) {
      uint64_t total = N;
      if (j == query[i].size() - 1) {
        total = n_i % N;
      }
      cout << "-- expanding one query ctxt into " << total << " ctxts " << endl;
      vector<Ciphertext> expanded_query_part =
          expand_query(query[i][j], total, client_id);
      expanded_query.insert(
          expanded_query.end(),
          std::make_move_iterator(expanded_query_part.begin()),
          std::make_move_iterator(expanded_query_part.end()));
      expanded_query_part.clear();
    }
    cout << "Server: expansion done " << endl;
    if (expanded_query.size() != n_i) {
      cout << " size mismatch!!! " << expanded_query.size() << ", " << n_i
           << endl;
    }

    // Transform expanded query to NTT, and ...
    if (i == 0) {
      for (uint32_t jj = 0; jj < expanded_query.size(); jj++) {
        evaluator_->transform_to_ntt_inplace(expanded_query[jj]);
      }
    }

    // Transform plaintext to NTT. If database is pre-processed, can skip
    // if ((!is_db_preprocessed_) || i > 0) {
    //   for (uint32_t jj = 0; jj < cur->size(); jj++) {
    //     evaluator_->transform_to_ntt_inplace((*cur)[jj],
    //                                          context_->first_parms_id());
    //   }
    // }

    for (uint64_t k = 0; k < product; k++) {
      if ((*cur)[k].is_zero()) {
        cout << k + 1 << "/ " << product << "-th ptxt = 0 " << endl;
      }
    }

    product /= n_i;

    vector<Ciphertext> intermediateCtxts(product);
    Ciphertext temp;

    if (i == 0) {
      for (uint64_t k = 0; k < product; k++) {

        evaluator_->multiply_plain(expanded_query[0], (*cur)[k],
                                   intermediateCtxts[k]);

        for (uint64_t j = 1; j < n_i; j++) {
          evaluator_->multiply_plain(expanded_query[j], (*cur)[k + j * product],
                                     temp);
          evaluator_->add_inplace(intermediateCtxts[k],
                                  temp); // Adds to first component.
        }
      }
    } else {
      for (uint64_t k = 0; k < product; k++) {

        evaluator_->multiply(expanded_query[0], intermediate_cipher[k],
                             intermediateCtxts[k]);

        for (uint64_t j = 1; j < n_i; j++) {
          evaluator_->multiply(expanded_query[j],
                               intermediate_cipher[k + j * product], temp);
          evaluator_->add_inplace(intermediateCtxts[k],
                                  temp); // Adds to first component.
        }
      }
    }
    if (i == 0) {
      for (uint32_t jj = 0; jj < intermediateCtxts.size(); jj++) {
        evaluator_->transform_from_ntt_inplace(intermediateCtxts[jj]);
      }
    }

    if (i == nvec.size() - 1) {
      assert(intermediateCtxts.size() == 1);

      seal::Blake2xbPRNGFactory factory;
      auto gen = factory.create();
      uint64_t mask = gen->generate() % enc_params_.plain_modulus().value();
      printf("mask: %lu\n", mask);
      // uint64_t mask = gen->generate() % enc_params_.plain_modulus().value();

      Plaintext mask_plain(N);
      mask_plain.set_zero();
      mask_plain[0] = mask;
      Ciphertext mask_cipher;
      encryptor_->encrypt(mask_plain, mask_cipher);

      evaluator_->add(intermediateCtxts[0], mask_cipher, mask_cipher);
      // evaluator_->multiply(mask_cipher, intermediateCtxts[0], mask_cipher);
      return make_pair(mask_cipher, mask);
    } else {
      intermediate_cipher.clear();
      intermediate_cipher.reserve(product);
      for (uint64_t rr = 0; rr < product; ++rr) {
        EncryptionParameters parms;

        intermediate_cipher.emplace_back(std::move(intermediateCtxts[rr]));
      }

      // intermediate_plain.clear();
      // intermediate_plain.reserve(pir_params_.expansion_ratio * product);
      // cur = &intermediate_plain;

      // for (uint64_t rr = 0; rr < product; rr++) {
      //   EncryptionParameters parms;
      //   if (pir_params_.enable_mswitching) {
      //     evaluator_->mod_switch_to_inplace(intermediateCtxts[rr],
      //                                       context_->last_parms_id());
      //     parms = context_->last_context_data()->parms();
      //   } else {
      //     parms = context_->first_context_data()->parms();
      //   }

      //   vector<Plaintext> plains =
      //       decompose_to_plaintexts(parms, intermediateCtxts[rr]);

      //   for (uint32_t jj = 0; jj < plains.size(); jj++) {
      //     intermediate_plain.emplace_back(plains[jj]);
      //   }
      // }
      // product = intermediate_plain.size(); // multiply by expansion rate.
    }
    cout << "Server: " << i + 1 << "-th recursion level finished " << endl;
    cout << endl;
  }
  cout << "reply generated!  " << endl;
  // This should never get here
  assert(0);
  vector<Ciphertext> fail(1);
  return make_pair(fail[0], 0UL);
}

inline vector<Ciphertext> PIRServer::expand_query(const Ciphertext &encrypted,
                                                  uint32_t m,
                                                  uint32_t client_id) {

  GaloisKeys &galkey = galoisKeys_[client_id];

  // Assume that m is a power of 2. If not, round it to the next power of 2.
  uint32_t logm = ceil(log2(m));
  Plaintext two("2");

  vector<int> galois_elts;
  auto n = enc_params_.poly_modulus_degree();
  if (logm > ceil(log2(n))) {
    throw logic_error("m > n is not allowed.");
  }
  for (int i = 0; i < ceil(log2(n)); i++) {
    galois_elts.push_back((n + exponentiate_uint(2, i)) /
                          exponentiate_uint(2, i));
  }

  vector<Ciphertext> temp;
  temp.push_back(encrypted);
  Ciphertext tempctxt;
  Ciphertext tempctxt_rotated;
  Ciphertext tempctxt_shifted;
  Ciphertext tempctxt_rotatedshifted;

  for (uint32_t i = 0; i < logm - 1; i++) {
    vector<Ciphertext> newtemp(temp.size() << 1);
    // temp[a] = (j0 = a (mod 2**i) ? ) : Enc(x^{j0 - a}) else Enc(0).  With
    // some scaling....
    int index_raw = (n << 1) - (1 << i);
    int index = (index_raw * galois_elts[i]) % (n << 1);

    for (uint32_t a = 0; a < temp.size(); a++) {

      evaluator_->apply_galois(temp[a], galois_elts[i], galkey,
                               tempctxt_rotated);

      // cout << "rotate " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_rotated) << ", ";

      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);

      // cout << "mul by x^pow: " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_shifted) << ", ";

      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);

      // cout << "mul by x^pow: " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_rotatedshifted) <<
      // ", ";

      // Enc(2^i x^j) if j = 0 (mod 2**i).
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                      newtemp[a + temp.size()]);
    }
    temp = newtemp;
    /*
    cout << "end: ";
    for (int h = 0; h < temp.size();h++){
        cout << client.decryptor_->invariant_noise_budget(temp[h]) << ", ";
    }
    cout << endl;
    */
  }
  // Last step of the loop
  vector<Ciphertext> newtemp(temp.size() << 1);
  int index_raw = (n << 1) - (1 << (logm - 1));
  int index = (index_raw * galois_elts[logm - 1]) % (n << 1);
  for (uint32_t a = 0; a < temp.size(); a++) {
    if (a >= (m - (1 << (logm - 1)))) { // corner case.
      evaluator_->multiply_plain(temp[a], two,
                                 newtemp[a]); // plain multiplication by 2.
      // cout << client.decryptor_->invariant_noise_budget(newtemp[a]) << ", ";
    } else {
      evaluator_->apply_galois(temp[a], galois_elts[logm - 1], galkey,
                               tempctxt_rotated);
      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);
      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                      newtemp[a + temp.size()]);
    }
  }

  vector<Ciphertext>::const_iterator first = newtemp.begin();
  vector<Ciphertext>::const_iterator last = newtemp.begin() + m;
  vector<Ciphertext> newVec(first, last);

  return newVec;
}

inline void PIRServer::multiply_power_of_X(const Ciphertext &encrypted,
                                           Ciphertext &destination,
                                           uint32_t index) {

  auto coeff_mod_count = enc_params_.coeff_modulus().size() - 1;
  auto coeff_count = enc_params_.poly_modulus_degree();
  auto encrypted_count = encrypted.size();

  // cout << "coeff mod count for power of X = " << coeff_mod_count << endl;
  // cout << "coeff count for power of X = " << coeff_count << endl;

  // First copy over.
  destination = encrypted;

  // Prepare for destination
  // Multiply X^index for each ciphertext polynomial
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                     coeff_count, index,
                                     enc_params_.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}

// void PIRServer::simple_set(uint64_t index, Plaintext pt) {
//   if (is_db_preprocessed_) {
//     evaluator_->transform_to_ntt_inplace(pt, context_->first_parms_id());
//   }
//   db_->operator[](index) = pt;
// }

// Ciphertext PIRServer::simple_query(uint64_t index) {
//   // There is no transform_from_ntt that takes a plaintext
//   Ciphertext ct;
//   Plaintext pt = db_->operator[](index);
//   evaluator_->multiply_plain(one_, pt, ct);
//   evaluator_->transform_from_ntt_inplace(ct);
//   return ct;
// }

void PIRServer::set_one_ct(Ciphertext one) {
  one_ = one;
  evaluator_->transform_to_ntt_inplace(one_);
}