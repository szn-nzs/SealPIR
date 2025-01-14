#ifndef longFUSEFILTER_H
#define longFUSEFILTER_H
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utility>
#include <vector>
#ifndef XOR_MAX_ITERATIONS
#define XOR_MAX_ITERATIONS                                                     \
  100 // probability of success should always be > 0.5 so 100 iterations is
      // highly unlikely
#endif

static uint32_t lff_hash_num = 3;
static int long_fuse_cmpfunc(const void *a, const void *b) {
  return (*(const uint64_t *)a - *(const uint64_t *)b);
}

// static size_t long_fuse_sort_and_remove_dup(uint64_t *keys, size_t length) {
//   qsort(keys, length, sizeof(uint64_t), long_fuse_cmpfunc);
//   size_t j = 1;
//   for (size_t i = 1; i < length; i++) {
//     if (keys[i] != keys[i - 1]) {
//       keys[j] = keys[i];
//       j++;
//     }
//   }
//   return j;
// }

/**
 * We start with a few utilities.
 ***/
static inline uint64_t long_fuse_murmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}
static inline uint64_t long_fuse_mix_split(uint64_t key, uint64_t seed) {
  return long_fuse_murmur64(key + seed);
}
static inline uint64_t long_fuse_rotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63)) | (n >> ((-c) & 63));
}
static inline uint32_t long_fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}
static inline uint64_t long_fuse_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}
static inline void test_long_fuse_addi(std::vector<uint64_t> &p,
                                       const std::vector<uint64_t> &q,
                                       uint64_t valueLength,
                                       uint64_t valueModulus) {
  assert(p.size() == valueLength && q.size() == valueLength);
  for (uint64_t i = 0; i < valueLength; ++i) {
    p[i] += q[i];
    p[i] %= valueModulus;
  }
}
static inline void long_fuse_addi(std::vector<uint64_t> &p,
                                  const std::vector<uint64_t> &q,
                                  uint64_t valueLength, uint64_t valueModulus) {
  assert(p.size() == valueLength && q.size() == valueLength);
  for (uint64_t i = 0; i < valueLength; ++i) {
    int64_t tmp_p = (int64_t)p[i], tmp_q = (int64_t)q[i];
    tmp_p += tmp_q;
    tmp_p = ((tmp_p % (int64_t)valueModulus) + (int64_t)valueModulus) %
            (int64_t)valueModulus;
    // tmp_p %= (int64_t)valueModulus;
    p[i] = (uint64_t)tmp_p;
    // p[i] += q[i];
    // p[i] %= (int64_t)valueModulus;
  }
}
static inline void long_fuse_subi(std::vector<uint64_t> &p,
                                  const std::vector<uint64_t> &q,
                                  uint64_t valueLength, uint64_t valueModulus) {
  assert(p.size() == valueLength && q.size() == valueLength);
  for (uint64_t i = 0; i < valueLength; ++i) {
    int64_t tmp_p = (int64_t)p[i], tmp_q = (int64_t)q[i];
    tmp_p -= tmp_q;
    tmp_p = ((tmp_p % (int64_t)valueModulus) + (int64_t)valueModulus) %
            (int64_t)valueModulus;
    // tmp_p %= (int64_t)valueModulus;
    p[i] = (uint64_t)tmp_p;
    // p[i] -= q[i];
    // p[i] %= (int64_t)valueModulus;
  }
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t long_fuse_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}
typedef struct long_fuse_parameters {
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint64_t ValueLongLength;
  uint64_t ValueModulus;
} long_fuse_params;

typedef struct long_fuse_s {
  long_fuse_params params;
  uint64_t Seed;
  std::vector<std::vector<uint64_t>> Fingerprints;
  // int64_t **Fingerprints;
} long_fuse_t;

// #ifdefs adapted from:
//  https://stackoverflow.com/a/50958815
#ifdef __SIZEOF_INT128__ // compilers supporting __uint128, e.g., gcc, clang
static inline uint64_t long_fuse_mulhi(uint64_t a, uint64_t b) {
  return ((__uint128_t)a * b) >> 64;
}
#elif defined(_M_X64) || defined(_MARM64) // MSVC
static inline uint64_t long_fuse_mulhi(uint64_t a, uint64_t b) {
  return __umulh(a, b);
}
#elif defined(_M_IA64)                    // also MSVC
static inline uint64_t long_fuse_mulhi(uint64_t a, uint64_t b) {
  unsigned __int64 hi;
  (void)_umul128(a, b, &hi);
  return hi;
}
#else // portable implementation using uint64_t
static inline uint64_t long_fuse_mulhi(uint64_t a, uint64_t b) {
  // Adapted from:
  //  https://stackoverflow.com/a/51587262

  /*
        This is implementing schoolbook multiplication:

                a1 a0
        X       b1 b0
        -------------
                   00  LOW PART
        -------------
                00
             10 10     MIDDLE PART
        +       01
        -------------
             01
        + 11 11        HIGH PART
        -------------
  */

  const uint64_t a0 = (uint32_t)a;
  const uint64_t a1 = a >> 32;
  const uint64_t b0 = (uint32_t)b;
  const uint64_t b1 = b >> 32;
  const uint64_t p11 = a1 * b1;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p00 = a0 * b0;

  // 64-bit product + two 32-bit values
  const uint64_t middle = p10 + (p00 >> 32) + (uint32_t)p01;

  /*
    Proof that 64-bit products can accumulate two more 32-bit values
    without overflowing:

    Max 32-bit value is 2^32 - 1.
    PSum = (2^32-1) * (2^32-1) + (2^32-1) + (2^32-1)
         = 2^64 - 2^32 - 2^32 + 1 + 2^32 - 1 + 2^32 - 1
         = 2^64 - 1
    Therefore the high half below cannot overflow regardless of input.
  */

  // high half
  return p11 + (middle >> 32) + (p01 >> 32);

  // low half (which we don't care about, but here it is)
  // (middle << 32) | (uint32_t) p00;
}
#endif

typedef struct long_hashes_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
} long_hashes_t;

static inline long_hashes_t
long_fuse_hash_batch(uint64_t hash, const long_fuse_params &params) {
  uint64_t hi = long_fuse_mulhi(hash, params.SegmentCountLength);
  long_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + params.SegmentLength;
  ans.h2 = ans.h1 + params.SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18) & params.SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&params.SegmentLengthMask;
  return ans;
}

static inline uint32_t long_fuse_hash(int index, uint64_t hash,
                                      const long_fuse_params &params) {
  uint64_t h = long_fuse_mulhi(hash, params.SegmentCountLength);
  h += index * params.SegmentLength;
  // keep the lower 36 bits
  uint64_t hh = hash & ((1UL << 36) - 1);
  // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
  h ^= (size_t)((hh >> (36 - 18 * index)) & params.SegmentLengthMask);
  return h;
}

// Report if the key is in the set, with false positive rate.
static inline std::vector<uint64_t>
long_fuse_decode(uint64_t key, const long_fuse_t *filter) {
  uint64_t hash = long_fuse_mix_split(key, filter->Seed);
  //   uint8_t f = long_fuse_fingerprint(hash);
  long_hashes_t hashes = long_fuse_hash_batch(hash, filter->params);
  if (key == 0) {
    printf("seed: %lu\n", filter->Seed);
    printf("hash: %lu\n", hash);
    printf("!!!!!!!!!!!!hashes: %u, %u, %u\n", hashes.h0, hashes.h1, hashes.h2);
  }
  std::vector<uint64_t> res(filter->params.ValueLongLength, 0);
  long_fuse_addi(res, filter->Fingerprints[hashes.h0],
                 filter->params.ValueLongLength, filter->params.ValueModulus);
  long_fuse_addi(res, filter->Fingerprints[hashes.h1],
                 filter->params.ValueLongLength, filter->params.ValueModulus);
  long_fuse_addi(res, filter->Fingerprints[hashes.h2],
                 filter->params.ValueLongLength, filter->params.ValueModulus);
  return res;
}

static inline uint32_t long_fuse_calculate_segment_length(uint32_t arity,
                                                          uint32_t size) {
  // These parameters are very sensitive. Replacing 'floor' by 'round' can
  // substantially affect the construction time.
  if (arity == 3) {
    return ((uint32_t)1) << (int)(floor(log((double)(size)) / log(3.33) +
                                        2.25));
  } else if (arity == 4) {
    return ((uint32_t)1) << (int)(floor(log((double)(size)) / log(2.91) - 0.5));
  } else {
    return 65536;
  }
}

static inline double long_fuse_max(double a, double b) {
  if (a < b) {
    return b;
  }
  return a;
}

static inline double long_fuse_calculate_size_factor(uint32_t arity,
                                                     uint32_t size) {
  if (arity == 3) {
    return long_fuse_max(1.125,
                         0.875 + 0.25 * log(1000000.0) / log((double)size));
  } else if (arity == 4) {
    return long_fuse_max(1.075,
                         0.77 + 0.305 * log(600000.0) / log((double)size));
  } else {
    return 2.0;
  }
}
static inline void long_fuse_gen_params(uint32_t size, uint64_t valueLongLength,
                                        uint64_t valueModulus,
                                        long_fuse_params &params) {
  uint32_t arity = 3;
  params.SegmentLength =
      size == 0 ? 4 : long_fuse_calculate_segment_length(arity, size);
  if (params.SegmentLength > 262144) {
    params.SegmentLength = 262144;
  }
  params.SegmentLengthMask = params.SegmentLength - 1;
  double sizeFactor =
      size <= 1 ? 0 : long_fuse_calculate_size_factor(arity, size);
  uint32_t capacity =
      size <= 1 ? 0 : (uint32_t)(round((double)size * sizeFactor));
  uint32_t initSegmentCount =
      (capacity + params.SegmentLength - 1) / params.SegmentLength -
      (arity - 1);
  params.ArrayLength = (initSegmentCount + arity - 1) * params.SegmentLength;
  params.SegmentCount =
      (params.ArrayLength + params.SegmentLength - 1) / params.SegmentLength;
  if (params.SegmentCount <= arity - 1) {
    params.SegmentCount = 1;
  } else {
    params.SegmentCount = params.SegmentCount - (arity - 1);
  }
  params.ArrayLength = (params.SegmentCount + arity - 1) * params.SegmentLength;
  params.SegmentCountLength = params.SegmentCount * params.SegmentLength;

  params.ValueLongLength = valueLongLength;
  params.ValueModulus = valueModulus;
}
// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call long_fuse_free(filter)
// size should be at least 2.
static inline bool long_fuse_allocate(const long_fuse_params &params,
                                      long_fuse_t *filter) {
  // long_fuse_gen_params(size, valueLongLength, valueModulus, filter->params);

  filter->params = params;
  filter->Fingerprints.resize(filter->params.ArrayLength);
  // filter->Fingerprints =
  //     (int64_t **)malloc(filter->ArrayLength * sizeof(int64_t *));
  for (uint64_t i = 0; i < filter->params.ArrayLength; ++i) {
    filter->Fingerprints[i].resize(filter->params.ValueLongLength);
    // filter->Fingerprints[i] =
    //     (int64_t *)calloc(filter->ValueLongLength, sizeof(int64_t));

    // memset(filter->Fingerprints[i].data(), 1,
    //        filter->ValueLongLength * sizeof(int64_t));
  }
  return true;
  // return filter->Fingerprints != NULL;
}

// report memory usage
// static inline size_t long_fuse_size_in_bytes(const long_fuse_t *filter) {
//   return filter->ArrayLength * sizeof(uint64_t) + sizeof(long_fuse_t);
// }

// release memory
static inline void long_fuse_free(long_fuse_t *filter) {
  // for (uint64_t i = 0; i < filter->ValueLongLength; ++i) {
  //   free(filter->Fingerprints[i]);
  // }
  // free(filter->Fingerprints);
  // filter->Fingerprints = NULL;
  filter->Seed = 0;
  filter->params.SegmentLength = 0;
  filter->params.SegmentLengthMask = 0;
  filter->params.SegmentCount = 0;
  filter->params.SegmentCountLength = 0;
  filter->params.ArrayLength = 0;
}

static inline uint8_t long_fuse_mod3(uint8_t x) { return x > 2 ? x - 3 : x; }

// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling long_fuse_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool long_fuse_populate(
    const std::vector<std::pair<uint64_t, std::vector<uint64_t>>> &keyValueMap,
    uint32_t size, uint64_t valueLongLength, uint64_t valueModulus,
    long_fuse_t *filter) {
  uint64_t rng_counter = 0x726b2b9d438b9d4d;
  filter->Seed = long_fuse_rng_splitmix64(&rng_counter);
  uint64_t *reverseOrder = (uint64_t *)calloc((size + 1), sizeof(uint64_t));
  uint32_t capacity = filter->params.ArrayLength;
  uint32_t *alone = (uint32_t *)malloc(capacity * sizeof(uint32_t));
  uint8_t *t2count = (uint8_t *)calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = (uint8_t *)malloc(size * sizeof(uint8_t));
  uint64_t *t2hash = (uint64_t *)calloc(capacity, sizeof(uint64_t));

  uint32_t blockBits = 1;
  while (((uint32_t)1 << blockBits) < filter->params.SegmentCount) {
    blockBits += 1;
  }
  uint32_t block = ((uint32_t)1 << blockBits);
  uint32_t *startPos = (uint32_t *)malloc((1 << blockBits) * sizeof(uint32_t));
  uint32_t h012[5];
  std::map<uint64_t, std::vector<uint64_t>> hashValueMap;

  if ((alone == NULL) || (t2count == NULL) || (reverseH == NULL) ||
      (t2hash == NULL) || (reverseOrder == NULL) || (startPos == NULL)) {
    free(alone);
    free(t2count);
    free(reverseH);
    free(t2hash);
    free(reverseOrder);
    free(startPos);
    return false;
  }
  reverseOrder[size] = 1;
  for (int loop = 0; true; ++loop) {
    if (loop + 1 > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system)
      // memset(filter->Fingerprints, ~0, filter->ArrayLength *
      // sizeof(int64_t));
      free(alone);
      free(t2count);
      free(reverseH);
      free(t2hash);
      free(reverseOrder);
      free(startPos);
      return false;
    }

    for (uint32_t i = 0; i < block; i++) {
      // important : i * size would overflow as a 32-bit number in some
      // cases.
      startPos[i] = ((uint64_t)i * size) >> blockBits;
    }

    uint64_t maskblock = block - 1;
    for (uint32_t i = 0; i < size; i++) {
      // for (auto iter = keyValueMap.begin(); iter != keyValueMap.end();
      // ++iter) {
      // ***********************************
      uint64_t hash = long_fuse_murmur64(keyValueMap[i].first + filter->Seed);
      hashValueMap[hash] = keyValueMap[i].second;
      // printf("hashvalue map size: %lu, valuelonglength: %lu\n",
      //        hashValueMap[hash].size(), filter->params.ValueLongLength);
      assert(hashValueMap[hash].size() == filter->params.ValueLongLength);

      uint64_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= maskblock;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index]++;
    }
    int error = 0;
    uint32_t duplicates = 0;
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      uint32_t h0 = long_fuse_hash(0, hash, filter->params);
      t2count[h0] += 4;
      t2hash[h0] ^= hash;
      uint32_t h1 = long_fuse_hash(1, hash, filter->params);
      t2count[h1] += 4;
      t2count[h1] ^= 1;
      t2hash[h1] ^= hash;
      uint32_t h2 = long_fuse_hash(2, hash, filter->params);
      t2count[h2] += 4;
      t2hash[h2] ^= hash;
      t2count[h2] ^= 2;
      // ************************去掉了，不知道有什么用
      // if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
      //   if (((t2hash[h0] == 0) && (t2count[h0] == 8)) ||
      //       ((t2hash[h1] == 0) && (t2count[h1] == 8)) ||
      //       ((t2hash[h2] == 0) && (t2count[h2] == 8))) {
      //     duplicates += 1;
      //     t2count[h0] -= 4;
      //     t2hash[h0] ^= hash;
      //     t2count[h1] -= 4;
      //     t2count[h1] ^= 1;
      //     t2hash[h1] ^= hash;
      //     t2count[h2] -= 4;
      //     t2count[h2] ^= 2;
      //     t2hash[h2] ^= hash;
      //   }
      // }
      error = (t2count[h0] < 4) ? 1 : error;
      error = (t2count[h1] < 4) ? 1 : error;
      error = (t2count[h2] < 4) ? 1 : error;
    }
    if (error) {
      memset(reverseOrder, 0, sizeof(uint64_t) * size);
      memset(t2count, 0, sizeof(uint8_t) * capacity);
      memset(t2hash, 0, sizeof(uint64_t) * capacity);
      filter->Seed = long_fuse_rng_splitmix64(&rng_counter);
      continue;
    }

    // End of key addition
    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (uint32_t i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      Qsize += ((t2count[i] >> 2) == 1) ? 1 : 0;
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2) == 1) {
        uint64_t hash = t2hash[index];

        h012[0] = long_fuse_hash(0, hash, filter->params);
        h012[1] = long_fuse_hash(1, hash, filter->params);
        h012[2] = long_fuse_hash(2, hash, filter->params);
        h012[3] = long_fuse_hash(0, hash, filter->params); // == h012[0];
        h012[4] = h012[1];
        uint8_t found = t2count[index] & 3;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        Qsize += ((t2count[other_index1] >> 2) == 2 ? 1 : 0);

        t2count[other_index1] -= 4;
        t2count[other_index1] ^= long_fuse_mod3(found + 1);
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        Qsize += ((t2count[other_index2] >> 2) == 2 ? 1 : 0);
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= long_fuse_mod3(found + 2);
        t2hash[other_index2] ^= hash;
      }
    }
    assert(duplicates == 0);
    if (stacksize + duplicates == size) {
      // success
      size = stacksize;
      break;
    }
    // 为了踢掉重复的key吗？
    // else if (duplicates > 0) {
    //   size = long_fuse_sort_and_remove_dup(keys, size);
    // }
    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    memset(t2count, 0, sizeof(uint8_t) * capacity);
    memset(t2hash, 0, sizeof(uint64_t) * capacity);
    filter->Seed = long_fuse_rng_splitmix64(&rng_counter);
  }

  assert(filter->Fingerprints.size() == filter->params.ArrayLength);
  for (uint64_t i = 0; i < filter->params.ArrayLength; ++i) {
    assert(filter->Fingerprints[i].size() == filter->params.ValueLongLength);
    // filter->Fingerprints[i][0] = 1;
    std::fill(filter->Fingerprints[i].begin(), filter->Fingerprints[i].end(),
              1);
  }

  // for (uint32_t i = size - 1; i < size; i--) {
  for (int32_t i = size - 1; i >= 0; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    assert(hashValueMap[hash].size() == filter->params.ValueLongLength);

    // uint8_t xor2 = long_fuse_fingerprint(hash);
    uint8_t found = reverseH[i];
    h012[0] = long_fuse_hash(0, hash, filter->params);
    h012[1] = long_fuse_hash(1, hash, filter->params);
    h012[2] = long_fuse_hash(2, hash, filter->params);
    h012[3] = h012[0];
    h012[4] = h012[1];
    // memset(filter->Fingerprints[h012[found]], 0,
    //        filter->ValueLongLength * sizeof(uint64_t));
    std::fill(filter->Fingerprints[h012[found]].begin(),
              filter->Fingerprints[h012[found]].end(), 0);
    long_fuse_subi(filter->Fingerprints[h012[found]],
                   filter->Fingerprints[h012[found + 1]],
                   filter->params.ValueLongLength, filter->params.ValueModulus);
    long_fuse_subi(filter->Fingerprints[h012[found]],
                   filter->Fingerprints[h012[found + 2]],
                   filter->params.ValueLongLength, filter->params.ValueModulus);

    long_fuse_addi(filter->Fingerprints[h012[found]], hashValueMap[hash],
                   filter->params.ValueLongLength, filter->params.ValueModulus);
  }

  free(alone);
  free(t2count);
  free(reverseH);
  free(t2hash);
  free(reverseOrder);
  free(startPos);

  return true;
}

#endif