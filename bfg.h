/*
 * bfg.h - Brute Force Generator Header
 */

#ifndef BFG_H
#define BFG_H

#include <stdint.h>

#define BF_CHARSMAX 4096
#define BF_MAX_LENGTH 256

typedef struct {
    uint32_t from;
    uint32_t to;
    uint32_t current;
    uint32_t crs_len;
    uint8_t state[BF_MAX_LENGTH];
    char *crs;
    char *ptr;
    uint32_t flags;
    uint64_t total_count;
    
    /* Extended features */
    uint32_t thread_id;
    uint32_t num_threads;
    uint64_t generated_count;
    bool cache_enabled;
} bf_options_t;

extern bf_options_t bf_options;

/* Core functions */
int32_t bf_init(char *arg);
char *bf_next(void);
uint64_t bf_get_pcount(void);

/* Wordlist functions */
typedef struct wordlist wordlist_t;
wordlist_t *bf_load_wordlist(const char *filename);
void bf_free_wordlist(wordlist_t *wl);
char *bf_get_word(wordlist_t *wl, uint32_t index);
char *bf_next_word(wordlist_t *wl);

/* Mutation functions */
typedef struct mutation_t mutation_t;
char *bf_mutate(const char *password, mutation_t *rules);

/* Thread functions */
void bf_start_threads(uint32_t num);
void bf_stop_threads(void);
void bf_pause_threads(void);
void bf_resume_threads(void);

/* Cache functions */
char *bf_next_cached(void);

/* Utility functions */
void bf_print_stats(void);

#endif /* BFG_H */
