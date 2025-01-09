#ifndef EMP_MYBASEOT_H__
#define EMP_MYBASEOT_H__
#pragma once
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <emp-tool/emp-tool.h>
#include <emp-tool/utils/block.h>
#include <emp-tool/utils/group.h>
#include <emp-tool/utils/utils.h>
#include <gsl/gsl>
#include <memory>
#include <span>
#include <vector>

namespace lpr21::ot {
// void print128_num(__m128i var) {
//   uint16_t val[8];
//   memcpy(val, &var, sizeof(val));
//   printf("Numerical: %i %i %i %i %i %i %i %i \n", val[0], val[1], val[2],
//          val[3], val[4], val[5], val[6], val[7]);
// }

class BaseOT {
public:
  using EType = std::vector<std::vector<emp::block>>;
  BaseOT(std::shared_ptr<emp::Group> _G, int64_t _length) : length(_length) {
    if (_G == nullptr) {
      emp::error("_G cannot be nullptr");
    }
    G = std::move(_G);
  }
  ~BaseOT() {}

protected:
  std::shared_ptr<emp::Group> G = nullptr;
  int64_t length;
};

class BaseOTSender : public BaseOT {
public:
  BaseOTSender(std::shared_ptr<emp::Group> _G, int64_t _length)
      : BaseOT(std::move(_G), _length) {}
  ~BaseOTSender() = default;

  const emp::Point &sendA() {
    G->get_rand_bn(a);
    A = G->mul_gen(a);

    return A;
  }

  EType sendE(std::vector<emp::Point> B, gsl::span<const emp::block> data0,
              gsl::span<const emp::block> data1) {
    emp::Point AaInv;
    AaInv = A.mul(a);
    AaInv = AaInv.inv();

    if (B.size() != length) {
      emp::error("B.size error\n");
    }
    if (data0.size() != length || data1.size() != length) {
      emp::error("data.size errot\n");
    }
    std::vector<emp::Point> BA(length);
    std::vector<emp::Point> BAaInv(length);
    for (int64_t i = 0; i < length; ++i) {
      BA[i] = B[i].mul(a);
      BAaInv[i] = BA[i].add(AaInv);
    }

    EType res;
    res.reserve(length);
    for (int64_t i = 0; i < length; ++i) {
      std::vector<emp::block> tmp(2);

      tmp[0] = emp::Hash::KDF(BA[i], i) ^ data0[i];
      tmp[1] = emp::Hash::KDF(BAaInv[i], i) ^ data1[i];
      res.emplace_back(std::move(tmp));
    }

    return res;
  }

private:
  emp::BigInt a;
  emp::Point A;
};

class BaseOTReceiver : public BaseOT {
public:
  BaseOTReceiver(std::shared_ptr<emp::Group> _G, int64_t _length)
      : BaseOT(std::move(_G), _length) {
    B.resize(length);
    bb.resize(length);
  }
  ~BaseOTReceiver() = default;

  const std::vector<emp::Point> &sendB(emp::Point A, gsl::span<const bool> b) {
    B.clear();
    bb.clear();
    B.resize(length);
    bb.resize(length);

    for (int64_t i = 0; i < length; ++i)
      G->get_rand_bn(bb[i]);
    for (int64_t i = 0; i < length; ++i) {
      B[i] = G->mul_gen(bb[i]);
      if (b[i])
        B[i] = B[i].add(A);
    }

    return B;
  }

  std::vector<emp::block> getM(emp::Point A, const EType &E,
                               gsl::span<const bool> b) {
    std::vector<emp::Point> As(length);
    std::vector<emp::block> data(length);
    for (int64_t i = 0; i < length; ++i) {
      As[i] = A.mul(bb[i]);
    }

    if (E.size() != length) {
      emp::error("E.size error\n");
    }
    if (b.size() != length) {
      emp::error("b.size error\n");
    }
    for (int64_t i = 0; i < length; ++i) {
      assert(E[i].size() == 2);
      data[i] = emp::Hash::KDF(As[i], i);

      if (b[i])
        data[i] = data[i] ^ E[i][1];
      else
        data[i] = data[i] ^ E[i][0];
    }

    return data;
  }

private:
  std::vector<emp::BigInt> bb;
  std::vector<emp::Point> B;
};
} // namespace lpr21::ot
#endif