#ifndef EMP_MYNOT_H__
#define EMP_MYNOT_H__
#include "myIKNP.hpp"
#include "myROT.hpp"
#include "mybaseOT.hpp"
#include <cstdint>
#include <cstdio>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/group.h>
#include <emp-tool/utils/utils.h>
#include <gsl/gsl>
#include <memory>
#include <span>
#include <vector>

namespace lpr21::ot {
const static int64_t ot_instance_num = 1000;
class myNOT {
public:
  myNOT(int64_t _maxChoice, int64_t _length)
      : maxChoice(_maxChoice), length(_length) {}

protected:
  int64_t maxChoice, length;
  emp::PRG prg;
  emp::MITCCRH<ot_bsize> mitccrh;
};
class myNOTSender : public myNOT {
public:
  myNOTSender(std::shared_ptr<myIKNPSender> _iknp_sender, int64_t _maxChoice,
              int64_t _length)
      : myNOT(_maxChoice, _length), iknp_sender(_iknp_sender), isSetS(false),
        isSetup(false) {}
  // myIKNPSender &getIKNPSender() { return iknp_sender; }
  const std::vector<emp::block> &getKey0() { return userkey0; }
  const std::vector<emp::block> &getKey1() { return userkey1; }

  emp::block setS() {
    emp::block s;
    prg.random_block(&s, 1);
    mitccrh.setS(s);

    isSetS = true;
    return s;
  }
  void setupNOT() {
    int64_t maxChoiceBitLength = std::ceil(log(maxChoice));

    userkey0.resize(maxChoiceBitLength);
    userkey1.resize(maxChoiceBitLength);

    emp::PRG prg(emp::fix_key);
    prg.random_block(userkey0.data(), maxChoiceBitLength);
    prg.random_block(userkey1.data(), maxChoiceBitLength);

    isSetup = true;
  }
  // void setupCOT() { iknp_sender->setupSend(); }
  // std::vector<emp::Point> baseOTMsg1(emp::Point A) {
  //   return iknp_sender->baseOTMsg1(A);
  // }
  // void baseOTGetData(emp::Point A, const BaseOT::EType &E) {
  //   iknp_sender->baseOTGetData(A, E);
  // }
  // void sendPre(const std::vector<std::vector<emp::block>> &U) {
  //   int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
  //   iknp_sender->sendPre(U, maxChoiceBitLength);
  // }
  // 上面是iknp的部分，生成ot_instance_num个OT实例，其中sender端持有q

  std::vector<std::vector<emp::block>> sendROT(const std::vector<uint8_t> &e) {
    if (!isSetS) {
      emp::error("s not set\n");
    }
    if (!isSetup) {
      emp::error("not setup\n");
    }
    int64_t maxChoiceBitLength = userkey0.size();
    if (e.size() != maxChoiceBitLength) {
      emp::error("e.size error\n");
    }

    // 这里要先执行iknp给q赋值,然后才能getQ
    std::vector<emp::block> data = iknp_sender->getNextQ(maxChoiceBitLength);

    std::vector<std::vector<emp::block>> pad;
    pad.resize(maxChoiceBitLength / ot_bsize + 1);
    for (int64_t i = 0; i < maxChoiceBitLength; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      pad[cnt].resize(2 * ot_bsize);

      for (int64_t j = i; j < min(i + ot_bsize, maxChoiceBitLength); ++j) {
        // t_i^(Delta&r_i)
        pad[cnt][2 * (j - i)] = data[j];
        // t_i^(Delta&\bar{r_i})
        pad[cnt][2 * (j - i) + 1] = data[j] ^ iknp_sender->getDelta();
      }
      mitccrh.hash<ot_bsize, 2>(pad[cnt].data());

      for (int64_t j = i; j < min(i + ot_bsize, maxChoiceBitLength); ++j) {
        // // x0^H(T^(Delta&r))
        // pad[cnt][2 * (j - i)] = pad[cnt][2 * (j - i)] ^ userkey0[j];
        // // x1^H(T^(Delta&\bar{r}))
        // pad[cnt][2 * (j - i) + 1] = pad[cnt][2 * (j - i) + 1] ^ userkey1[j];

        emp::block tmp1 = pad[cnt][2 * (j - i) + e[j]] ^ userkey0[j];
        // x1^H(T^(Delta&\bar{r}))
        emp::block tmp2 = pad[cnt][2 * (j - i) + (1 - e[j])] ^ userkey1[j];
        pad[cnt][2 * (j - i)] = tmp1;
        pad[cnt][2 * (j - i) + 1] = tmp2;
      }
    }

    return pad;
  }

  std::vector<emp::block> sendNOT(gsl::span<const emp::block> data) {
    if (!isSetS) {
      emp::error("s not set\n");
    }
    if (data.size() != length * maxChoice) {
      emp::error("data size error\n");
    }

    int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
    std::vector<emp::block> res;
    res.resize(maxChoice * length);
    int64_t tmpi;
    emp::AES_KEY aeskey;
    for (int64_t i = 0; i < maxChoice * length; i += length) {
      tmpi = i / length;
      for (int64_t j = 0; j < length; ++j) {
        res[i + j] = emp::makeBlock(0, 0);
      }
      emp::block userkey = emp::makeBlock(0, 0);
      for (int64_t j = 0; j < maxChoiceBitLength; ++j) {
        if (tmpi & 1) {
          // res[i] ^= userkey1[j];
          userkey ^= userkey1[j];
        } else {
          // res[i] ^= userkey0[j];
          userkey ^= userkey0[j];
        }
        tmpi >>= 1;
      }
      // AES_set_encrypt_key(res[i], &aeskey);
      AES_set_encrypt_key(userkey, &aeskey);

      memcpy(res.data() + i, data.data() + i, sizeof(emp::block) * length);
      AES_ecb_encrypt_blks(res.data() + i, length, &aeskey);
    }

    return res;
  }

private:
  bool isSetup = false;
  bool isSetS = false;
  std::vector<emp::block> userkey0, userkey1;
  std::shared_ptr<myIKNPSender> iknp_sender;
};
class myNOTReceiver : public myNOT {
public:
  myNOTReceiver(std::shared_ptr<myIKNPReceiver> _iknp_receiver,
                int64_t _maxChoice, int64_t _length)
      : myNOT(_maxChoice, _length), iknp_receiver(_iknp_receiver),
        isSetS(false), isSetup(false) {}
  // myNOTReceiver(std::shared_ptr<emp::Group> _G, int64_t _maxChoice,
  //               int64_t _length)
  //     : myNOT(_maxChoice, _length), iknp_receiver(_G), isSetS(false),
  //       isSetup(false) {}
  // myIKNPReceiver &getIKNPReceiver() { return iknp_receiver; }

  void setupNOT(int64_t r) {
    this->r = r;
    isSetup = true;
  }
  void setS(emp::block s) {
    mitccrh.setS(s);
    isSetS = true;
  }
  // void setupCOT() { iknp_receiver->setupRecv(); }
  // emp::Point baseOTMsg1() { return iknp_receiver->baseOTMsg1(); }
  // BaseOT::EType baseOTMsg2(std::vector<emp::Point> B) {
  //   return iknp_receiver->baseOTMsg2(B);
  // }
  // std::vector<std::vector<emp::block>> recvPre() {
  //   int64_t tmpr = r;
  //   int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
  //   bool *b = new bool[maxChoiceBitLength];
  //   for (int64_t i = 0; i < maxChoiceBitLength; ++i) {
  //     b[i] = tmpr & 1;
  //     tmpr >>= 1;
  //   }

  //   return iknp_receiver->recvPre(gsl::span(b, maxChoiceBitLength),
  //                                maxChoiceBitLength);
  // }
  // 上面是iknp的部分，生成ot_instance_num个OT实例，其中recv端持有T

  std::vector<uint8_t> recvROTPre() {
    int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
    int64_t tmpr = r;
    bool *b = new bool[maxChoiceBitLength];
    for (int64_t i = 0; i < maxChoiceBitLength; ++i) {
      b[i] = tmpr & 1;
      tmpr >>= 1;
    }

    vector<uint8_t> res = iknp_receiver->getNextChoice(maxChoiceBitLength);
    for (uint64_t i = 0; i < maxChoiceBitLength; ++i) {
      res[i] = (uint8_t)b[i] ^ res[i];
    }

    return res;
  }

  std::vector<emp::block> recvROT(std::vector<std::vector<emp::block>> res) {
    if (!isSetS) {
      emp::error("s not set\n");
    }
    if (!isSetup) {
      emp::error("not setup\n");
    }

    // 这里要先执行iknp给T赋值,然后才能getT
    int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
    std::vector<emp::block> T = iknp_receiver->getNextT(maxChoiceBitLength);
    std::vector<emp::block> data;
    data.resize(maxChoiceBitLength);

    int64_t tmpr = r;
    bool *b = new bool[maxChoiceBitLength];
    for (int64_t i = 0; i < maxChoiceBitLength; ++i) {
      b[i] = tmpr & 1;
      tmpr >>= 1;
    }

    emp::block pad[ot_bsize];
    for (int64_t i = 0; i < maxChoiceBitLength; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      // T接下来的ot_size行
      memcpy(pad, T.data() + i,
             min(ot_bsize, maxChoiceBitLength - i) * sizeof(emp::block));
      // 哈希 计算H(t)=H(t)
      // 当r=0时就是H(T^(Delta&r))，当r=1时就是H(T^(Delta&\bar{r}))
      mitccrh.hash<ot_bsize, 1>(pad);

      for (int64_t j = 0; j < ot_bsize and j < maxChoiceBitLength - i; ++j) {
        data[i + j] = res[cnt][2 * j + b[i + j]] ^ pad[j];
      }
    }

    delete[] b;
    return data;
  }

  std::vector<emp::block> recvNOT(std::vector<emp::block> key,
                                  std::vector<emp::block> res) {
    if (res.size() != maxChoice * length) {
      emp::error("res.size error\n");
    }
    int64_t maxChoiceBitLength = std::ceil(log(maxChoice));
    if (key.size() != maxChoiceBitLength) {
      emp::error("key.size error\n");
    }

    int64_t tmpr = r;
    bool *b = new bool[maxChoiceBitLength];
    for (int64_t i = 0; i < maxChoiceBitLength; ++i) {
      b[i] = tmpr & 1;
      tmpr >>= 1;
    }

    emp::block userkey = emp::makeBlock(0, 0);
    emp::AES_KEY aeskey;
    for (int64_t i = 0; i < maxChoiceBitLength; ++i) {
      userkey ^= key[i];
    }
    AES_set_decrypt_key(userkey, &aeskey);

    std::vector<emp::block> data;
    data.resize(length);
    memcpy(data.data(), res.data() + r * length, length * sizeof(emp::block));
    AES_ecb_decrypt_blks(data.data(), length, &aeskey);

    delete[] b;
    return data;
  }

private:
  bool isSetup = false;
  bool isSetS = false;
  int64_t r;
  std::shared_ptr<myIKNPReceiver> iknp_receiver;
};
} // namespace lpr21::ot
#endif