#pragma once

#include "pir.hpp"
#include "pir_client.hpp"
#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

class PIRServer {
public:
  const static std::uint8_t bf_id = 0;
  const static std::uint8_t lff_id = 1;
  using DBType = std::vector<std::pair<uint64_t, std::vector<uint8_t>>>;
  // using DBType =
  //     std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>;
  PIRServer(const seal::EncryptionParameters &enc_params,
            const PirParams &pir_params, const PIRClient &client);

  // NOTE: server takes over ownership of db and frees it when it exits.
  // Caller cannot free db
  uint64_t set_database(const DBType &db_vec, std::uint64_t ele_num,
                        std::uint64_t ele_size);
  void set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&bf_db,
                    std::unique_ptr<std::vector<seal::Plaintext>> &&lff_db);
  // void set_database(const std::unique_ptr<const std::uint8_t[]> &bytes,
  //                   std::uint64_t ele_num, std::uint64_t ele_size);
  void preprocess_database();

  std::vector<seal::Ciphertext> expand_query(const seal::Ciphertext &encrypted,
                                             std::uint32_t m,
                                             std::uint32_t client_id);

  PirQuery deserialize_query(std::stringstream &stream);
  PirReply generate_reply(PirQuery &query, std::uint32_t client_id,
                          std::uint8_t db_id);
  // Serializes the reply into the provided stream and returns the number of
  // bytes written
  int serialize_reply(PirReply &reply, std::stringstream &stream);

  void set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey);

  // Below simple operations are for interacting with the database WITHOUT PIR.
  // So they can be used to modify a particular element in the database or
  // to query a particular element (without privacy guarantees).
  void simple_set(std::uint64_t index, seal::Plaintext pt);
  seal::Ciphertext simple_query(std::uint64_t index);
  void set_one_ct(seal::Ciphertext one);

private:
  seal::EncryptionParameters enc_params_; // SEAL parameters
  PirParams pir_params_;                  // PIR parameters
  std::unique_ptr<Database> bf_db_;
  std::unique_ptr<Database> lff_db_;
  bool is_db_preprocessed_;
  std::map<int, seal::GaloisKeys> galoisKeys_;
  std::unique_ptr<seal::Evaluator> evaluator_;
  // std::unique_ptr<seal::BatchEncoder> encoder_;
  std::shared_ptr<seal::SEALContext> context_;

  // This is only used for simple_query
  seal::Ciphertext one_;

  const PIRClient &client_;

  void multiply_power_of_X(const seal::Ciphertext &encrypted,
                           seal::Ciphertext &destination, std::uint32_t index);
};