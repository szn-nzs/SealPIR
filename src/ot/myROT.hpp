#ifndef EMP_MYCOT_H__
#define EMP_MYCOT_H__
#include "myIKNP.hpp"
#include "mybaseOT.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/group.h>
#include <emp-tool/utils/mitccrh.h>
#include <emp-tool/utils/utils.h>
#include <gsl/gsl>
#include <gsl/span>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace lpr21::ot {
const static int64_t ot_bsize = 8;

class myROT {
protected:
  emp::PRG prg;
  emp::MITCCRH<ot_bsize> mitccrh;
};
class myROTSender : public myROT {
public:
  std::shared_ptr<myIKNPSender> iknp_sender;

  myROTSender(std::shared_ptr<myIKNPSender> _iknp_sender)
      : iknp_sender(_iknp_sender), isSetS(false) {}
  // myROTSender(std::shared_ptr<emp::Group> _G)
  //     : iknp_sender(_G), isSetS(false) {}
  // myIKNPSender &getIKNPSender() { return iknp_sender; }

  emp::block setS() {
    emp::block s;
    prg.random_block(&s, 1);
    mitccrh.setS(s);

    isSetS = true;
    return s;
  }

  std::vector<std::vector<emp::block>> sendROT(int64_t length) {
    if (!isSetS) {
      emp::error("hash seed not set\n");
    }
    // 这里要先执行iknp给q赋值,然后才能getQ
    std::vector<emp::block> data = iknp_sender->getNextQ(length);

    std::vector<std::vector<emp::block>> pad;
    pad.resize(length / ot_bsize + 1);
    for (int64_t i = 0; i < length; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      pad[cnt].resize(2 * ot_bsize);

      for (int64_t j = i; j < std::min(i + ot_bsize, length); ++j) {
        // t_i^(Delta&r_i)
        pad[cnt][2 * (j - i)] = data[j];
        // t_i^(Delta&\bar{r_i})
        pad[cnt][2 * (j - i) + 1] = data[j] ^ iknp_sender->getDelta();
      }
      mitccrh.hash<ot_bsize, 2>(pad[cnt].data());
    }

    return pad;
  }

  std::vector<std::vector<emp::block>> sendOT(gsl::span<const emp::block> data0,
                                              gsl::span<const emp::block> data1,
                                              const std::vector<uint8_t> &e,
                                              int64_t length) {
    if (!isSetS) {
      emp::error("hash seed not set\n");
    }
    if (data0.size() != length || data1.size() != length) {
      emp::error("data size error\n");
    }
    if (e.size() != length) {
      emp::error("e size error\n");
    }

    // 这里要先执行iknp给q赋值,然后才能getQ
    std::vector<emp::block> data = iknp_sender->getNextQ(length);

    std::vector<std::vector<emp::block>> pad;
    pad.resize(length / ot_bsize + 1);
    for (int64_t i = 0; i < length; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      pad[cnt].resize(2 * ot_bsize);

      for (int64_t j = i; j < min(i + ot_bsize, length); ++j) {
        // t_i^(Delta&r_i)
        pad[cnt][2 * (j - i)] = data[j];
        // t_i^(Delta&\bar{r_i})
        pad[cnt][2 * (j - i) + 1] = data[j] ^ iknp_sender->getDelta();
      }
      mitccrh.hash<ot_bsize, 2>(pad[cnt].data());

      for (int64_t j = i; j < min(i + ot_bsize, length); ++j) {
        // // x0^H(T^(Delta&r))
        // pad[cnt][2 * (j - i)] = pad[cnt][2 * (j - i)] ^ data0[j];
        // // x1^H(T^(Delta&\bar{r}))
        // pad[cnt][2 * (j - i) + 1] = pad[cnt][2 * (j - i) + 1] ^ data1[j];

        // x0^H(T^(Delta&r))
        emp::block tmp1 = pad[cnt][2 * (j - i) + e[j]] ^ data0[j];
        // x1^H(T^(Delta&\bar{r}))
        emp::block tmp2 = pad[cnt][2 * (j - i) + (1 - e[j])] ^ data1[j];
        pad[cnt][2 * (j - i)] = tmp1;
        pad[cnt][2 * (j - i) + 1] = tmp2;
      }
    }

    return pad;
  }

private:
  bool isSetS = false;
};
class myROTReceiver : public myROT {
public:
  myROTReceiver(std::shared_ptr<myIKNPReceiver> _iknp_receiver)
      : iknp_receiver(_iknp_receiver), isSetS(false) {}
  // myIKNPReceiver &getIKNPReceiver() { return *iknp_receiver; }
  // myROTReceiver(std::shared_ptr<emp::Group> _G)
  //     : iknp_receiver(_G), isSetS(false) {}
  // myIKNPReceiver &getIKNPReceiver() { return iknp_receiver; }

  std::shared_ptr<myIKNPReceiver> iknp_receiver;

  void setS(emp::block s) {
    mitccrh.setS(s);
    isSetS = true;
  }
  std::vector<emp::block> recvROT(gsl::span<const bool> r, int64_t length) {
    if (!isSetS) {
      emp::error("hash seed not set\n");
    }
    if (r.size() != length) {
      emp::error("r.size error\n");
    }

    // 这里要先执行iknp给T赋值,然后才能getT
    std::vector<emp::block> T = iknp_receiver->getNextT(length);
    std::vector<emp::block> data;
    data.resize(length);

    emp::block pad[ot_bsize];
    for (int64_t i = 0; i < length; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      // T接下来的ot_size行
      memcpy(pad, T.data() + i, min(ot_bsize, length - i) * sizeof(emp::block));
      // 哈希 计算H(t)=H(t)
      // 当r=0时就是H(T^(Delta&r))，当r=1时就是H(T^(Delta&\bar{r}))
      mitccrh.hash<ot_bsize, 1>(pad);
    }
    return data;
  }

  std::vector<uint8_t> recvOTPre(gsl::span<bool> r, int64_t length) {
    if (r.size() != length) {
      emp::error("r.size error\n");
    }

    vector<uint8_t> res = iknp_receiver->getNextChoice(length);
    for (uint64_t i = 0; i < length; ++i) {
      res[i] = (uint8_t)r[i] ^ res[i];
    }

    return res;
  }

  std::vector<emp::block>
  recvOT(const std::vector<std::vector<emp::block>> &res, gsl::span<bool> r,
         int64_t length) {
    if (!isSetS) {
      emp::error("hash seed not set\n");
    }

    // 这里要先执行iknp给T赋值,然后才能getT
    std::vector<emp::block> T = iknp_receiver->getNextT(length);
    std::vector<emp::block> data;
    data.resize(length);

    emp::block pad[ot_bsize];
    for (int64_t i = 0; i < length; i += ot_bsize) {
      int64_t cnt = i / ot_bsize;
      // T接下来的ot_size行
      memcpy(pad, T.data() + i, min(ot_bsize, length - i) * sizeof(emp::block));
      // 哈希 计算H(t)=H(t)
      // 当r=0时就是H(T^(Delta&r))，当r=1时就是H(T^(Delta&\bar{r}))
      mitccrh.hash<ot_bsize, 1>(pad);

      for (int64_t j = 0; j < ot_bsize and j < length - i; ++j) {
        data[i + j] = res[cnt][2 * j + r[i + j]] ^ pad[j];
      }
    }
    return data;
  }

private:
  bool isSetS = false;
  // std::shared_ptr<myIKNPReceiver> iknp_receiver;
};
} // namespace lpr21::ot
#endif