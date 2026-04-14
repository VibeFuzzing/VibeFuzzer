#ifndef AFL_FUZZ_H
#define AFL_FUZZ_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @brief  Structure representing an entry in the AFL fuzzing queue. This structure contains information about the test case, including its ID, depth in the fuzzing tree, bitmap size for coverage tracking, whether it is favored for fuzzing, whether it has new coverage, and the filename where the test case is stored. This structure is used by the AFL state to manage the fuzzing queue and track test cases.
 * 
 */
struct queue_entry {
    int id;
    unsigned long long depth;
    int bitmap_size;
    bool favored;
    bool has_new_cov;
    const char *fname;
};

/**
 * @brief  Structure representing the state of the AFL fuzzing process. This structure contains the number of items in the fuzzing queue and a pointer to an array of pointers to queue entries. The AFL state is used to manage the fuzzing process, track test cases, and provide information to the custom mutator functions.
 * 
 */
typedef struct afl_state {
    int queued_items;
    struct queue_entry **queue_buf;
} afl_state_t;

#endif // AFL_FUZZ_H
