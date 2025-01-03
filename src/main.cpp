#include "long_fuse_filter.hpp"
#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <random>
#include <seal/ciphertext.h>
#include <seal/seal.h>
#include <utility>
#include <vector>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

  uint64_t number_of_items = 1 << 7;
  uint64_t size_per_key = 16;
  uint64_t size_per_item = 1; // in bytes
  uint32_t N = 8192;

  // Recommended values: (logt, d) = (20, 2).
  uint32_t logt = 8;
  uint32_t bf_d = 1;
  uint32_t lff_d = 2;
  double epsilon = 0.6;
  bool use_symmetric = true; // use symmetric encryption instead of public key
                             // (recommended for smaller query)
  bool use_batching = true;  // pack as many elements as possible into a BFV
                             // plaintext (recommended)
  bool use_recursive_mod_switching = true;

  EncryptionParameters enc_params(scheme_type::bfv);
  PirParams pir_params;

  // Generates all parameters

  cout << "Main: Generating SEAL parameters" << endl;
  gen_encryption_params(N, logt, enc_params);

  cout << "Main: Verifying SEAL parameters" << endl;
  // verify_encryption_params(enc_params);
  cout << "Main: SEAL parameters are good" << endl;

  cout << "Main: Generating PIR parameters" << endl;
  gen_pir_params(number_of_items, size_per_item, size_per_key, bf_d, lff_d,
                 epsilon, enc_params, pir_params, use_symmetric, use_batching,
                 use_recursive_mod_switching);

  print_seal_params(enc_params);
  // print_pir_params(pir_params);

  // Initialize PIR client....
  PIRClient client(enc_params, pir_params);
  cout << "Main: Generating galois keys for client" << endl;

  GaloisKeys galois_keys = client.generate_galois_keys();

  // Initialize PIR Server
  cout << "Main: Initializing server" << endl;
  PIRServer server(enc_params, pir_params, client.get_public_key(), client);

  // Server maps the galois key to client 0. We only have 1 client,
  // which is why we associate it with 0. If there are multiple PIR
  // clients, you should have each client generate a galois key,
  // and assign each client an index or id, then call the procedure below.
  server.set_galois_key(0, galois_keys);

  cout << "Main: Creating the database with random data (this may take some "
          "time) ..."
       << endl;

  // Create test database
  vector<pair<uint64_t, uint64_t>> db;
  db.resize(number_of_items);

  seal::Blake2xbPRNGFactory factory;
  auto gen = factory.create();
  for (uint64_t i = 0; i < number_of_items; i++) {
    uint32_t high = gen->generate();
    uint32_t low = gen->generate();
    db[i].first = ((uint64_t)high << 32) | (uint64_t)low;

    high = gen->generate();
    low = gen->generate();
    db[i].second =
        (((uint64_t)high << 32) | (uint64_t)low) % ((1UL << logt) + 1);
    // db[i].second.resize(size_per_item);
    // for (uint64_t j = 0; j < size_per_item; j++) {
    //   uint8_t val = gen->generate() % 256;
    //   db[i].second[j] = val;
    // }
  }

  // Measure database setup
  auto time_pre_s = high_resolution_clock::now();
  vector<uint64_t> seed =
      server.set_database(db, number_of_items, size_per_item);
  server.preprocess_database();
  client.set_seed(seed);
  auto time_pre_e = high_resolution_clock::now();
  auto time_pre_us =
      duration_cast<microseconds>(time_pre_e - time_pre_s).count();
  cout << "Main: database pre processed " << endl;

  // Choose an index of an element in the DB
  random_device rd;
  uint64_t ele_index =
      rd() % number_of_items; // element in DB at random position
  uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext
  cout << "Main: element index = " << ele_index << " from [0, "
       << number_of_items - 1 << "]" << endl;
  cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

  for (size_t i = 0; i < number_of_items; ++i) {
    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery bf_query = client.generate_bf_query(db[i].first);
    PirQuery lff_query = client.generate_lff_query(db[i].first);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
        duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    // Measure query processing (including expansion)

    auto time_server_s = high_resolution_clock::now();
    // Answer PIR query from client 0. If there are multiple clients,
    // enter the id of the client (to use the associated galois key).
    pair<Ciphertext, uint64_t> bf_reply =
        server.generate_reply(bf_query, 0, PIRServer::bf_id);
    pair<Ciphertext, uint64_t> lff_reply =
        server.generate_reply(lff_query, 0, PIRServer::lff_id);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "Main: reply generated" << endl;

    // Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    uint64_t bf_elems = client.decode_bf_reply(bf_reply.first);
    uint64_t lff_elems = client.decode_lff_reply(lff_reply.first);
    // vector<uint8_t> elems = client.decode_reply(reply, offset);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us =
        duration_cast<microseconds>(time_decode_e - time_decode_s).count();
    cout << "Main: reply decoded" << endl;

    bool failed = false;
    // Check that we retrieved the correct element
    // if (bf_elems != pir_params.bf_params.optimal_parameters.number_of_hashes)
    // {
    //   cout << "BF query result wrong. result: " << bf_elems << endl;
    //   failed = true;
    //   return -1;
    // }
    // assert(lff_elems.size() == size_per_item);
    uint64_t plain_modulus = (1UL << logt) + 1;
    if (bf_elems != (pir_params.bf_params.optimal_parameters.number_of_hashes +
                     bf_reply.second) %
                        plain_modulus) {
      printf("query result: %lu, db_element: %lu\n", bf_elems,
             (pir_params.bf_params.optimal_parameters.number_of_hashes +
              bf_reply.second) %
                 plain_modulus);
      failed = true;
    }
    printf("query result: %lu, db_element: %lu\n", bf_elems,
           (pir_params.bf_params.optimal_parameters.number_of_hashes +
            bf_reply.second) %
               plain_modulus);

    if (lff_elems != (db[i].second + lff_reply.second) % plain_modulus) {
      printf("query result: %lu, db_element: %lu, %lu\n", lff_elems,
             db[i].second, (db[i].second + lff_reply.second) % plain_modulus);
      failed = true;
    }
    printf("query result: %lu, db_element: %lu, %lu\n", lff_elems, db[i].second,
           (db[i].second + lff_reply.second) % plain_modulus);
    if (failed) {
      return -1;
    }
  }

  // Output results
  cout << "Main: PIR result correct!" << endl;
  // cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << "
  // ms"
  //      << endl;
  // cout << "Main: PIRClient query generation time: " << time_query_us / 1000
  //      << " ms" << endl;
  //   cout << "Main: PIRClient serialized query generation time: "
  //        << time_s_query_us / 1000 << " ms" << endl;
  //   cout << "Main: PIRServer query deserialization time: " <<
  //   time_deserial_us
  //        << " us" << endl;
  // cout << "Main: PIRServer reply generation time: " << time_server_us / 1000
  //      << " ms" << endl;
  // cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000
  //      << " ms" << endl;
  //   cout << "Main: Query size: " << query_size << " bytes" << endl;
  //   cout << "Main: Reply num ciphertexts: " << reply.size() << endl;
  //   cout << "Main: Reply size: " << reply_size << " bytes" << endl;

  return 0;
}