#pragma once

#include "pir.hpp"
#include <cstdint>
#include <memory>
#include <seal/ciphertext.h>
#include <seal/publickey.h>
#include <vector>

using namespace std;

class PIRClient {
public:
  const static std::uint8_t bf_id = 0;
  const static std::uint8_t lff_id = 1;
  PIRClient(const seal::EncryptionParameters &encparms,
            const PirParams &pir_params);
  void set_seed(std::vector<std::uint64_t> seed);
  seal::PublicKey get_public_key();

  // PirQuery generate_query(std::uint64_t desiredIndex);
  PirQuery generate_bf_query(uint64_t desiredKey);
  PirQuery generate_lff_query(uint64_t desiredKey);
  // Serializes the query into the provided stream and returns number of bytes
  // written
  int generate_serialized_query(std::uint64_t desiredIndex,
                                std::stringstream &stream);
  seal::Plaintext decode_reply(const seal::Ciphertext &reply, uint8_t db_id);

  std::vector<uint64_t> extract_coeffs(seal::Plaintext pt);
  std::vector<uint64_t> extract_coeffs(seal::Plaintext pt,
                                       std::uint64_t offset);
  uint64_t extract_bf_bytes(seal::Plaintext pt);
  std::vector<uint8_t> extract_lff_bytes(seal::Plaintext pt);

  uint64_t decode_bf_reply(const seal::Ciphertext &replyt);

  // std::vector<uint8_t> decode_lff_reply(const seal::Ciphertext &reply);
  uint64_t decode_lff_reply(const seal::Ciphertext &reply);

  seal::Plaintext decrypt(seal::Ciphertext ct) const;

  seal::GaloisKeys generate_galois_keys();

  // Index and offset of an element in an FV plaintext
  uint64_t get_fv_index(uint64_t element_index);
  uint64_t get_fv_offset(uint64_t element_index);

  // Only used for simple_query
  seal::Ciphertext get_one();

  seal::Plaintext replace_element(seal::Plaintext pt,
                                  std::vector<std::uint64_t> new_element,
                                  std::uint64_t offset);

private:
  seal::EncryptionParameters enc_params_;
  PirParams pir_params_; // PIR parameters

  seal::PublicKey public_key_;
  std::unique_ptr<seal::Encryptor> encryptor_;
  std::unique_ptr<seal::Decryptor> decryptor_;
  std::unique_ptr<seal::Evaluator> evaluator_;
  std::unique_ptr<seal::KeyGenerator> keygen_;
  // std::unique_ptr<seal::BatchEncoder> encoder_;
  std::shared_ptr<seal::SEALContext> context_;

  // vector<vector<uint64_t>> indices_; // the indices for retrieval.
  vector<uint64_t> inverse_scales_;
  vector<uint64_t> seed_;

  friend class PIRServer;
};
