#ifndef EMP_MYIKNP_H__
#define EMP_MYIKNP_H__
#include "mybaseOT.hpp"
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/utils.h>
#include <gsl/gsl>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace lpr21::ot {
const static int64_t block_size = 1024 * 2;

class myIKNP {
public:
  myIKNP() {}

protected:
  // IKNPOptions options;
  emp::PRG prg;
};

class myIKNPSender : public myIKNP {
public:
  myIKNPSender(std::shared_ptr<emp::Group> _G)
      : ot_receiver(_G, 128), set_Q(false), Q_used_idx(0) {}
  const BaseOTReceiver &getOTReceiver() { return ot_receiver; }
  const emp::block &getDelta() { return Delta; }

  std::vector<emp::block> getNextQ(uint64_t length) {
    if (!set_Q) {
      emp::error("Q not set\n");
    } else if (Q_used_idx + length >= q.size()) {
      set_Q = false;
      Q_used_idx = 0;
      emp::error("Q not set\n");
    }

    std::vector<emp::block> tmp_Q = std::vector<emp::block>(
        q.begin() + Q_used_idx, q.begin() + Q_used_idx + length);
    Q_used_idx += length;
    assert(tmp_Q.size() == length);
    return std::move(tmp_Q);
    // return q;
  }

  void setupSend() {
    // 生成一个选择向量s，长度为128
    prg.random_bool(s, 128);
    Delta = emp::bool_to_block(s);
  }
  const std::vector<emp::Point> &baseOTMsg1(emp::Point A) {
    return ot_receiver.sendB(A, s);
  }
  void baseOTGetData(emp::Point A, const BaseOT::EType &E) {
    std::vector<emp::block> data = ot_receiver.getM(A, E, s);
    for (int64_t i = 0; i < 128; ++i) {
      k0[i] = data[i];
      G0[i].reseed(&k0[i]);
    }
  }

  void sendPre(const std::vector<std::vector<emp::block>> &U, int64_t length) {
    q.clear();
    q.resize(length);

    int64_t j = 0;
    emp::block local_out[block_size];

    for (; j < length / block_size; ++j) {
      sendPreBlock(U[j], q.data() + j * block_size, block_size);
    }
    int64_t remain = length % block_size;
    if (remain > 0) {
      sendPreBlock(U[j], local_out, remain);
      memcpy(q.data() + j * block_size, local_out, sizeof(emp::block) * remain);
    }
    set_Q = true;
  }

private:
  bool set_Q = false;
  bool s[128];
  uint64_t Q_used_idx = 0;
  emp::block k0[128], Delta;
  emp::PRG G0[128];
  std::vector<emp::block> q;
  BaseOTReceiver ot_receiver;

  void sendPreBlock(const std::vector<emp::block> &U, emp::block *out,
                    int64_t len) {
    emp::block t[block_size];
    memset(t, 0, block_size * sizeof(emp::block));
    int64_t local_block_size = (len + 127) / 128 * 128;

    for (int64_t i = 0; i < 128; ++i) {
      // G
      G0[i].random_data(t + (i * block_size / 128), local_block_size / 8);
      if (s[i]) {
        emp::xorBlocks_arr(
            t + (i * block_size / 128), t + (i * block_size / 128),
            U.data() + (i * block_size / 128), local_block_size / 128);
      }
    }
    emp::sse_trans((uint8_t *)(out), (uint8_t *)t, 128, block_size);
  }
};

class myIKNPReceiver : public myIKNP {
public:
  myIKNPReceiver(std::shared_ptr<emp::Group> _G)
      : ot_sender(_G, 128), set_T(false), set_choice(false), T_used_idx(0),
        choice_used_idx(0) {}
  const BaseOTSender &getOTSender() { return ot_sender; }
  std::vector<emp::block> getNextT(uint64_t length) {
    if (!set_T) {
      emp::error("T not set\n");
    } else if (T_used_idx + length >= T.size()) {
      set_T = false;
      T_used_idx = 0;
      emp::error("T not set\n");
    }

    std::vector<emp::block> tmp_T = std::vector<emp::block>(
        T.begin() + T_used_idx, T.begin() + T_used_idx + length);
    T_used_idx += length;
    assert(tmp_T.size() == length);
    return std::move(tmp_T);
    // return T;
  }
  std::vector<uint8_t> getNextChoice(uint64_t length) {
    if (!set_choice) {
      emp::error("choice not set\n");
    } else if (choice_used_idx + length >= choice.size()) {
      set_choice = false;
      choice_used_idx = 0;
      emp::error("choice not set\n");
    }

    std::vector<uint8_t> tmp_choice =
        std::vector<uint8_t>(choice.begin() + choice_used_idx,
                             choice.begin() + choice_used_idx + length);
    choice_used_idx += length;
    assert(tmp_choice.size() == length);
    return std::move(tmp_choice);
    // return choice;
  }

  void setupRecv() {
    prg.random_block(k0, 128);
    prg.random_block(k1, 128);

    for (int64_t i = 0; i < 128; ++i) {
      G0[i].reseed(&k0[i]);
      G1[i].reseed(&k1[i]);
    }
  }
  const emp::Point &baseOTMsg1() { return ot_sender.sendA(); }
  BaseOT::EType baseOTMsg2(std::vector<emp::Point> B) {
    return ot_sender.sendE(B, k0, k1);
  }

  std::vector<std::vector<emp::block>> recvPre(gsl::span<const bool> r,
                                               int64_t length) {
    if (r.size() != length) {
      emp::error("r.size error\n");
    }
    T.clear();
    T.resize(length);
    choice.clear();
    choice.resize(length);
    for (uint64_t i = 0; i < length; ++i) {
      choice[i] = (uint8_t)r[i];
    }
    std::vector<std::vector<emp::block>> res;

    emp::block *block_r = new emp::block[(length + 127) / 128];
    for (int64_t i = 0; i < length / 128; ++i)
      block_r[i] = emp::bool_to_block(&r[i * 128]);
    if (length % 128 != 0) {
      bool tmp_bool_array[128];
      memset(tmp_bool_array, 0, 128);
      int64_t start_point = (length / 128) * 128;
      memcpy(tmp_bool_array, &r[start_point], length % 128);
      block_r[length / 128] = emp::bool_to_block(tmp_bool_array);
    }

    res.reserve(length / block_size + 1);
    int64_t j = 0;
    for (; j < length / block_size; ++j) {
      std::vector<emp::block> tmp =
          recvPreBlock(T.data() + j * block_size,
                       gsl::span(block_r + (j * block_size / 128), block_size));
      res.emplace_back(std::move(tmp));
    }
    int64_t remain = length % block_size;
    if (remain > 0) {
      emp::block local_out[block_size];
      std::vector<emp::block> tmp = recvPreBlock(
          local_out, gsl::span(block_r + (j * block_size / 128), remain));
      memcpy(T.data() + j * block_size, local_out, sizeof(emp::block) * remain);
      res.emplace_back(std::move(tmp));
    }
    delete[] block_r;

    set_T = true;
    set_choice = true;
    return res;
  }

private:
  bool set_T = false;
  bool set_choice = false;
  uint64_t T_used_idx = 0;
  uint64_t choice_used_idx = 0;
  emp::block k0[128], k1[128];
  emp::PRG G0[128], G1[128];
  std::vector<emp::block> T;
  std::vector<uint8_t> choice;
  BaseOTSender ot_sender;

  std::vector<emp::block> recvPreBlock(emp::block *out,
                                       gsl::span<const emp::block> r) {
    int64_t len = r.size();
    emp::block t[block_size];
    memset(t, 0, block_size * sizeof(emp::block));
    std::vector<emp::block> tmp;
    tmp.clear();
    tmp.resize(block_size);

    int64_t local_block_size = (len + 127) / 128 * 128;
    for (int64_t i = 0; i < 128; ++i) {
      G0[i].random_data(t + (i * block_size / 128), local_block_size / 8);
      G1[i].random_data(tmp.data() + (i * block_size / 128),
                        local_block_size / 8);
      emp::xorBlocks_arr(
          tmp.data() + (i * block_size / 128), t + (i * block_size / 128),
          tmp.data() + (i * block_size / 128), local_block_size / 128);
      emp::xorBlocks_arr(tmp.data() + (i * block_size / 128), r.data(),
                         tmp.data() + (i * block_size / 128),
                         local_block_size / 128);
    }

    //转置
    emp::sse_trans((uint8_t *)(out), (uint8_t *)t, 128, block_size);
    return tmp;
  }
};

} // namespace lpr21::ot
#endif
