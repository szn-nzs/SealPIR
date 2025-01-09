#pragma once

#include "ot/myIKNP.hpp"
#include "ot/myNOT.hpp"
#include "ot/myROT.hpp"
#include "pir.hpp"
#include "pir_client.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/group.h>
#include <map>
#include <memory>
#include <seal/ciphertext.h>
#include <seal/publickey.h>
#include <utility>
#include <vector>

namespace lpr21::sealpir {
class PIRServer {
public:
  const static std::uint8_t bf_id = 0;
  const static std::uint8_t lff_id = 1;
  using DBType = std::vector<std::pair<uint64_t, uint64_t>>;
  // using DBType = std::vector<std::pair<uint64_t, std::vector<uint8_t>>>;
  using KVMapType = std::vector<std::pair<uint64_t, std::vector<uint64_t>>>;
  // using DBType =
  //     std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>;
  ot::myROTSender sender_;
  ot::myROTReceiver receiver_;
  ot::myNOTSender not_sender_;

  PIRServer(const seal::EncryptionParameters &enc_params,
            const PirParams &pir_params, const seal::PublicKey &public_key,
            const PIRClient &client,
            std::shared_ptr<ot::myIKNPSender> iknp_sender,
            std::shared_ptr<ot::myIKNPReceiver> iknp_receiver);

  // NOTE: server takes over ownership of db and frees it when it exits.
  // Caller cannot free db
  std::vector<uint64_t> set_database(const DBType &db_vec,
                                     std::uint64_t ele_num,
                                     std::uint64_t ele_size);
  void set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&bf_db,
                    std::unique_ptr<std::vector<seal::Plaintext>> &&lff_db);
  // void set_database(const std::unique_ptr<const std::uint8_t[]> &bytes,
  //                   std::uint64_t ele_num, std::uint64_t ele_size);
  void preprocess_database();

  std::vector<seal::Ciphertext> expand_query(const seal::Ciphertext &encrypted,
                                             std::uint32_t m,
                                             std::uint32_t client_id);

  seal::Ciphertext generate_reply(PirQuery &query, std::uint32_t client_id,
                                  std::uint8_t db_id);
  std::pair<seal::Ciphertext, std::uint64_t>
  generate_bf_reply(PirQuery &query, std::uint32_t client_id);
  std::pair<seal::Ciphertext, std::uint64_t>
  generate_lff_reply(PirQuery &query, seal::Ciphertext weight,
                     std::uint32_t client_id);

  int serialize_reply(PirReply &reply, std::stringstream &stream);

  void set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey);

  // not
  emp::block setS() { return not_sender_.setS(); }
  void setupNOT() { not_sender_.setupNOT(); }
  std::vector<std::vector<emp::block>> sendROT(const std::vector<uint8_t> &e) {
    return not_sender_.sendROT(e);
  }
  std::pair<uint64_t, std::vector<emp::block>> sendNOT(uint64_t r_prime) {
    std::random_device rd;
    std::mt19937 gen(rd());
    uint64_t bs = gen() & 1;

    uint64_t k = pir_params_.bf_params.optimal_parameters.number_of_hashes;
    uint64_t plain_modulus = enc_params_.plain_modulus().value();
    uint64_t idx = (plain_modulus + k - r_prime) % plain_modulus;
    idx = idx % (k + 1);
    printf("bs: %lu, idx: %lu\n", bs, idx);

    std::vector<emp::block> data(k + 1);
    for (uint64_t i = 0; i < k + 1; ++i) {
      data[i] = emp::makeBlock(0, bs);
    }
    data[idx] = emp::makeBlock(0, bs ^ 1);

    auto res = not_sender_.sendNOT(gsl::span(data.data(), data.size()));
    return std::make_pair(bs, res);
  }

  // value or default

private:
  seal::EncryptionParameters enc_params_; // SEAL parameters
  PirParams pir_params_;                  // PIR parameters
  std::unique_ptr<Database> bf_db_;
  std::unique_ptr<Database> lff_db_;
  bool is_db_preprocessed_;
  std::map<int, seal::GaloisKeys> galoisKeys_;
  std::unique_ptr<seal::Evaluator> evaluator_;
  std::unique_ptr<seal::Encryptor> encryptor_;
  std::shared_ptr<seal::SEALContext> context_;

  const PIRClient &client_;

  void multiply_power_of_X(const seal::Ciphertext &encrypted,
                           seal::Ciphertext &destination, std::uint32_t index);
};
} // namespace lpr21::sealpir