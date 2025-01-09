#pragma once

#include "ot/myNOT.hpp"
#include "ot/myROT.hpp"
#include "pir.hpp"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <seal/ciphertext.h>
#include <seal/publickey.h>
#include <vector>

using namespace std;

namespace lpr21::sealpir {
class PIRClient {
public:
  const static std::uint8_t bf_id = 0;
  const static std::uint8_t lff_id = 1;
  lpr21::ot::myROTSender sender_;
  lpr21::ot::myROTReceiver receiver_;
  lpr21::ot::myNOTReceiver not_receiver_;

  PIRClient(const seal::EncryptionParameters &encparms,
            const PirParams &pir_params,
            std::shared_ptr<ot::myIKNPSender> iknp_sender,
            std::shared_ptr<ot::myIKNPReceiver> iknp_receiver);
  void set_seed(std::vector<std::uint64_t> seed);
  seal::PublicKey get_public_key();
  uint64_t get_weight();

  // PirQuery generate_query(std::uint64_t desiredIndex);
  PirQuery generate_bf_query(uint64_t desiredKey);
  std::pair<seal::Ciphertext, PirQuery>
  generate_lff_query_and_weight(uint64_t desiredKey);
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

  // not
  void setupNOT(uint64_t r) {
    uint64_t k = pir_params_.bf_params.optimal_parameters.number_of_hashes;
    not_receiver_.setupNOT(r % (k + 1));
    printf("r: %lu\n", r % (k + 1));
  }
  void setS(emp::block s) { not_receiver_.setS(s); }
  std::vector<uint8_t> recvROTPre() { return not_receiver_.recvROTPre(); }
  std::vector<emp::block> recvROT(std::vector<std::vector<emp::block>> res) {
    return not_receiver_.recvROT(res);
  }
  std::vector<emp::block> recvNOT(std::vector<emp::block> key,
                                  std::vector<emp::block> res) {
    return not_receiver_.recvNOT(key, res);
  }

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

  vector<uint64_t> seed_;
  uint64_t w_;

  friend class PIRServer;
};
} // namespace lpr21::sealpir