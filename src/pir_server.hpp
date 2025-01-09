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
  using KVMapType = std::vector<std::pair<uint64_t, std::vector<uint64_t>>>;

  PIRServer(const seal::EncryptionParameters &enc_params,
            const PirParams &pir_params, const seal::PublicKey &public_key,
            const PIRClient &client,
            std::shared_ptr<ot::myIKNPSender> iknp_sender,
            std::shared_ptr<ot::myIKNPReceiver> iknp_receiver);

  std::vector<uint64_t> set_database(const DBType &db_vec,
                                     std::uint64_t ele_num,
                                     std::uint64_t ele_size);
  void set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&bf_db,
                    std::unique_ptr<std::vector<seal::Plaintext>> &&lff_db);
  void preprocess_database();

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
  emp::block setNOTS();
  void setupNOT();
  std::vector<std::vector<emp::block>> sendROT(const std::vector<uint8_t> &e);
  std::pair<uint64_t, std::vector<emp::block>> sendNOT(uint64_t r_prime);

  // value or default
  // as sender
  emp::block setS();
  std::vector<std::vector<emp::block>> sendOT(uint64_t q, uint64_t vs,
                                              uint64_t default_v,
                                              const std::vector<uint8_t> &e);
  // as receiver
  void setS(emp::block s);
  std::vector<uint8_t> recvOTPre();
  std::vector<emp::block>
  recvOT(const std::vector<std::vector<emp::block>> &res);

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

  ot::myROTSender sender_;
  ot::myROTReceiver receiver_;
  ot::myNOTSender not_sender_;

  uint64_t bs_;
  const PIRClient &client_;

  void multiply_power_of_X(const seal::Ciphertext &encrypted,
                           seal::Ciphertext &destination, std::uint32_t index);
  std::vector<seal::Ciphertext> expand_query(const seal::Ciphertext &encrypted,
                                             std::uint32_t m,
                                             std::uint32_t client_id);
};
} // namespace lpr21::sealpir