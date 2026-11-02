#ifndef ZK9_PQ_WITHDRAW32_VERIFIER_H
#define ZK9_PQ_WITHDRAW32_VERIFIER_H
#include <stddef.h>
#include <stdint.h>
/* 0 valid, 1 invalid, -1 uninitialized. Keeper checks ledger/registration. */
int32_t zk9_pq_withdraw32_init(void);
int32_t zk9_pq_withdraw32_verify(const uint8_t *, size_t, uint64_t, const uint8_t *, size_t);
#endif
