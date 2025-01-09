#include "long_fuse_filter.hpp"
#include "ot/myIKNP.hpp"
#include "ot/myNOT.hpp"
#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/utils.h>
#include <gsl/gsl>
#include <gsl/span>
#include <memory>
#include <random>
#include <seal/ciphertext.h>
#include <seal/seal.h>
#include <utility>
#include <vector>

using namespace std::chrono;
using namespace std;
using namespace seal;
using namespace lpr21::sealpir;

int main(int argc, char *argv[]) {

  uint64_t number_of_items = 1 << 6;
  uint64_t size_per_key = 16;
  uint64_t size_per_item = 1; // in bytes
  uint32_t N = 8192;

  // Recommended values: (logt, d) = (20, 2).
  uint32_t logt = 8;
  uint32_t bf_d = 2;
  uint32_t lff_d = 2;
  double epsilon = 1;
  bool use_symmetric = true; // use symmetric encryption instead of public key
                             // (recommended for smaller query)
  bool use_batching = true;  // pack as many elements as possible into a BFV
                             // plaintext (recommended)
  bool use_recursive_mod_switching = true;

  EncryptionParameters enc_params(scheme_type::bfv);
  PirParams pir_params;

  // ****************************************Generates all parameters

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

  shared_ptr<emp::Group> G = make_shared<emp::Group>();
  shared_ptr<lpr21::ot::myIKNPSender> iknp_sender_s =
      make_shared<lpr21::ot::myIKNPSender>(G);
  shared_ptr<lpr21::ot::myIKNPReceiver> iknp_receiver_s =
      make_shared<lpr21::ot::myIKNPReceiver>(G);
  shared_ptr<lpr21::ot::myIKNPSender> iknp_sender_c =
      make_shared<lpr21::ot::myIKNPSender>(G);
  shared_ptr<lpr21::ot::myIKNPReceiver> iknp_receiver_c =
      make_shared<lpr21::ot::myIKNPReceiver>(G);

  // ****************************************Initialize PIR client....
  PIRClient client(enc_params, pir_params, iknp_sender_c, iknp_receiver_c);
  cout << "Main: Generating galois keys for client" << endl;

  GaloisKeys galois_keys = client.generate_galois_keys();

  // ****************************************Initialize PIR Server
  cout << "Main: Initializing server" << endl;
  PIRServer server(enc_params, pir_params, client.get_public_key(), client,
                   iknp_sender_s, iknp_receiver_s);

  server.set_galois_key(0, galois_keys);

  cout << "Main: Creating the database with random data (this may take some "
          "time) ..."
       << endl;

  // ****************************************Create test database
  vector<pair<uint64_t, uint64_t>> db;
  db.resize(number_of_items);

  std::random_device rd;
  std::mt19937_64 gen(rd());
  for (uint64_t i = 0; i < number_of_items; i++) {
    db[i].first = gen();
    // db[i].first = i;
    db[i].second = gen() % ((1UL << logt) + 1);
  }

  // ****************************************Measure database setup
  auto time_pre_s = high_resolution_clock::now();
  vector<uint64_t> seed =
      server.set_database(db, number_of_items, size_per_item);
  server.preprocess_database();
  client.set_seed(seed);
  auto time_pre_e = high_resolution_clock::now();
  auto time_pre_us =
      duration_cast<microseconds>(time_pre_e - time_pre_s).count();
  cout << "Main: database pre processed " << endl;

  // ****************************************generate OT instances
  emp::PRG prg(emp::fix_key);
  emp::PRG prg2;
  uint64_t length = 1 << 20;
  bool *r = new bool[length];
  prg2.random_bool(r, length);

  iknp_sender_c->setupSend();
  iknp_receiver_s->setupRecv();
  emp::Point A1 = iknp_receiver_s->baseOTMsg1();
  std::vector<emp::Point> B1 = iknp_sender_c->baseOTMsg1(A1);
  lpr21::ot::BaseOT::EType E1 = iknp_receiver_s->baseOTMsg2(B1);
  iknp_sender_c->baseOTGetData(A1, E1);
  vector<vector<emp::block>> U1 =
      iknp_receiver_s->recvPre(gsl::span(r, length), length);
  iknp_sender_c->sendPre(U1, length);

  iknp_sender_s->setupSend();
  iknp_receiver_c->setupRecv();
  emp::Point A2 = iknp_receiver_c->baseOTMsg1();
  std::vector<emp::Point> B2 = iknp_sender_s->baseOTMsg1(A2);
  lpr21::ot::BaseOT::EType E2 = iknp_receiver_c->baseOTMsg2(B2);
  iknp_sender_s->baseOTGetData(A2, E2);
  vector<vector<emp::block>> U2 =
      iknp_receiver_c->recvPre(gsl::span(r, length), length);
  iknp_sender_s->sendPre(U2, length);

  server.receiver_.setS(client.sender_.setS());
  client.receiver_.setS(server.sender_.setS());

  // uint64_t ele_index = gen() % number_of_items;
  for (uint64_t ele_index = 0; ele_index < number_of_items; ++ele_index) {
    // ****************************************Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery bf_query = client.generate_bf_query(db[ele_index].first);
    auto lff_query = client.generate_lff_query_and_weight(db[ele_index].first);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us =
        duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    // ****************************************Measure query processing
    // (including expansion)
    auto time_server_s = high_resolution_clock::now();
    pair<Ciphertext, uint64_t> bf_reply = server.generate_bf_reply(bf_query, 0);
    pair<Ciphertext, uint64_t> lff_reply =
        server.generate_lff_reply(lff_query.second, lff_query.first, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us =
        duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout << "Main: reply generated" << endl;

    // ****************************************Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    uint64_t bf_elems = client.decode_bf_reply(bf_reply.first);
    uint64_t lff_elems = client.decode_lff_reply(lff_reply.first);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us =
        duration_cast<microseconds>(time_decode_e - time_decode_s).count();
    cout << "Main: reply decoded" << endl;

    bool failed = false;
    // ****************************************Check that we retrieved the
    // correct element
    uint64_t plain_modulus = (1UL << logt) + 1;
    if ((bf_elems + bf_reply.second) % plain_modulus !=
        pir_params.bf_params.optimal_parameters.number_of_hashes) {
      printf("bloom filter query result: %lu, mask: %lu, num of hash: %u\n",
             bf_elems, bf_reply.second,
             pir_params.bf_params.optimal_parameters.number_of_hashes);
      printf("ele_idx: %lu\n", ele_index);
      failed = true;
    }

    if ((lff_elems + lff_reply.second) % plain_modulus !=
        (db[ele_index].second * client.get_weight()) % plain_modulus) {
      printf("fuse filter query result: %lu, db_element: %lu, mask: %lu\n",
             lff_elems, db[ele_index].second, lff_reply.second);
      failed = true;
    }

    if (failed) {
      return -1;
    }

    // ****************************************compute bs and bc
    uint64_t r_client = bf_elems;
    uint64_t r_server = bf_reply.second;

    printf("r: %lu, r_prime: %lu\n", r_client, r_server);
    server.setupNOT();
    client.setupNOT(r_client);
    client.setS(server.setS());
    std::vector<uint8_t> ee = client.recvROTPre();
    vector<vector<emp::block>> pad0 = server.sendROT(ee);
    vector<emp::block> key = client.recvROT(pad0);

    auto pad1 = server.sendNOT(r_server);
    vector<emp::block> data00 = client.recvNOT(key, pad1.second);

    uint64_t bs = pad1.first;
    uint64_t bc = ((uint64_t *)&data00[0])[0];
    bool is_error = false;
    if ((bs ^ bc) != 1) {
      printf("000ot error\n");
      is_error = true;
    }

    // ****************************************Value or Default
    length = 1;
    uint64_t vs = lff_reply.second;
    uint64_t vc = lff_elems;
    uint64_t sj = gen() % plain_modulus;
    uint64_t default_v = 0;
    uint64_t Delta = gen() % plain_modulus;

    emp::block *m0_c = new emp::block[1];
    emp::block *m1_c = new emp::block[1];
    m0_c[0] = emp::makeBlock(0, Delta + bc * vc);
    m1_c[0] = emp::makeBlock(0, Delta + (1 - bc) * vc);
    bool *rr = new bool[1];
    rr[0] = bs;

    vector<uint8_t> e = server.receiver_.recvOTPre(gsl::span(rr, 1), 1);
    vector<vector<emp::block>> pad =
        client.sender_.sendOT(gsl::span(m0_c, 1), gsl::span(m1_c, 1), e, 1);
    vector<emp::block> data = server.receiver_.recvOT(pad, gsl::span(rr, 1), 1);
    assert(data.size() == 1);

    uint64_t q = ((uint64_t *)&data[0])[0];
    uint8_t b = bs ^ bc;
    if (q % plain_modulus != (Delta + b * vc) % plain_modulus) {
      printf("111ot error\n");
      is_error = true;
    }

    emp::block *m0_s = new emp::block[1];
    emp::block *m1_s = new emp::block[1];
    m0_s[0] = emp::makeBlock(0, q + bs * vs + (1 - bs) * default_v);
    m1_s[0] = emp::makeBlock(0, q + (1 - bs) * vs + bs * default_v);
    rr[0] = bc;

    e = client.receiver_.recvOTPre(gsl::span(rr, 1), 1);
    pad = server.sender_.sendOT(gsl::span(m0_s, 1), gsl::span(m1_s, 1), e, 1);
    data = client.receiver_.recvOT(pad, gsl::span(rr, 1), 1);
    assert(data.size() == 1);

    uint64_t q1 = ((uint64_t *)&data[0])[0];
    if (q1 != q + b * vs + (1 - b) * default_v) {
      printf("222ot error\n");
      is_error = true;
    }

    uint64_t output = q1 - Delta;
    printf("vs: %lu, vc: %lu, Delta: %lu\n", vs, vc, Delta);
    printf("output: %lu, db idx: %lu, weight: %lu\n", output,
           db[ele_index].second, client.get_weight());

    if (b == 1) {
      if (output % plain_modulus !=
          (db[ele_index].second * client.get_weight()) % plain_modulus) {
        printf("ot error\n");
        is_error = true;
      }
    } else {
      if (output % plain_modulus != default_v) {
        printf("ot error\n");
        is_error = true;
      }
    }

    if (is_error) {
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