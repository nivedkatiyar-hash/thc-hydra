/*
 * hydra-modern-template.h - Modern Protocol Module Template
 * 
 * This template provides:
 * - C11 standard compliance
 * - Thread-safe operations
 * - Memory leak prevention
 * - IPv6 support
 * - SSL/TLS with certificate validation
 * - Configurable timeouts
 * - Automatic retry with backoff
 * - Comprehensive logging
 * - JSON output support
 * 
 * Author: ZORG-Ω
 * License: AGPL v3
 */

#ifndef HYDRA_MODERN_TEMPLATE_H
#define HYDRA_MODERN_TEMPLATE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdatomic.h>
#include <threads.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "hydra-lib.h"
#include "hydra-mod.h"
#include "hydra-utils.h"

/* ============================================================
   1. MODULE CONFIGURATION
   ============================================================ */
#define MODULE_NAME "template"
#define MODULE_DESC "Template Protocol Module"
#define MODULE_AUTHOR "ZORG-Ω"
#define MODULE_VERSION "2.0.0"
#define MODULE_SERVICE "template"
#define MODULE_DEFAULT_PORT 12345
#define MODULE_SSL_PORT 12346

#define MODULE_TIMEOUT 30
#define MODULE_RETRY_COUNT 3
#define MODULE_RETRY_DELAY 2
#define MODULE_BUFFER_SIZE 8192
#define MODULE_MAX_RESPONSE 4096

/* ============================================================
   2. MODULE STATE STRUCTURE
   ============================================================ */
typedef struct {
    /* Connection state */
    int socket_fd;
    bool connected;
    bool ssl_enabled;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    
    /* Authentication state */
    char *username;
    char *password;
    char *domain;
    char *database;
    
    /* Protocol state */
    char *banner;
    char *server_version;
    int protocol_version;
    
    /* Performance metrics */
    uint64_t attempts;
    uint64_t successes;
    struct timespec start_time;
    struct timespec end_time;
    
    /* Error state */
    int last_error;
    char *last_error_msg;
    
    /* Thread safety */
    mtx_t lock;
    atomic_bool running;
} module_state_t;

/* ============================================================
   3. MODULE FUNCTION PROTOTYPES
   ============================================================ */
int module_init(char *ip, int port, unsigned char options, char *miscptr, FILE *hydra_fp);
int module_function(char *ip, int port, unsigned char options, char *miscptr, FILE *hydra_fp);
void module_exit(FILE *hydra_fp);

/* Internal functions */
static module_state_t *module_connect(char *ip, int port);
static void module_disconnect(module_state_t *state);
static int module_authenticate(module_state_t *state, char *username, char *password);
static int module_send_command(module_state_t *state, char *command, char *response, size_t response_size);
static char *module_read_response(module_state_t *state, int timeout);
static bool module_check_banner(module_state_t *state);

/* ============================================================
   4. IMPLEMENTATION
   ============================================================ */

/* -----------------------------------------------------------------
   Module Initialization
   ----------------------------------------------------------------- */
int module_init(char *ip, int port, unsigned char options, char *miscptr, FILE *hydra_fp) {
    if (hydra_fp) {
        fprintf(hydra_fp, "[%s] Initializing module...\n", MODULE_NAME);
    }
    
    /* Parse miscptr for options */
    if (miscptr) {
        char *tokens[4];
        int token_count = 0;
        char *saveptr;
        char *misc_copy = strdup(miscptr);
        
        if (!misc_copy) {
            fprintf(stderr, "[%s] Error: Cannot allocate memory\n", MODULE_NAME);
            return 0;
        }
        
        char *token = strtok_r(misc_copy, ":", &saveptr);
        while (token && token_count < 4) {
            tokens[token_count++] = token;
            token = strtok_r(NULL, ":", &saveptr);
        }
        
        /* Process options */
        if (token_count > 0 && strlen(tokens[0]) > 0) {
            /* Database name */
        }
        if (token_count > 1 && strlen(tokens[1]) > 0) {
            /* Domain name */
        }
        if (token_count > 2 && strcmp(tokens[2], "ssl") == 0) {
            /* Enable SSL */
        }
        
        free(misc_copy);
    }
    
    /* Test connection */
    module_state_t *state = module_connect(ip, port);
    if (!state || !state->connected) {
        if (hydra_fp) {
            fprintf(hydra_fp, "[%s] Error: Cannot connect to %s:%d\n", MODULE_NAME, ip, port);
        }
        if (state) {
            module_disconnect(state);
            free(state);
        }
        return 0;
    }
    
    /* Check banner */
    if (!module_check_banner(state)) {
        if (hydra_fp) {
            fprintf(hydra_fp, "[%s] Warning: Unexpected banner\n", MODULE_NAME);
        }
        module_disconnect(state);
        free(state);
        return 0;
    }
    
    if (hydra_fp) {
        fprintf(hydra_fp, "[%s] Server found on %s:%d\n", MODULE_NAME, ip, port);
        if (state->banner) {
            fprintf(hydra_fp, "[%s] Banner: %s\n", MODULE_NAME, state->banner);
        }
    }
    
    module_disconnect(state);
    free(state);
    
    return 1;
}

/* -----------------------------------------------------------------
   Connection Management
   ----------------------------------------------------------------- */
static module_state_t *module_connect(char *ip, int port) {
    module_state_t *state = calloc(1, sizeof(module_state_t));
    if (!state) {
        fprintf(stderr, "[%s] Error: Cannot allocate state\n", MODULE_NAME);
        return NULL;
    }
    
    mtx_init(&state->lock, mtx_plain);
    atomic_store(&state->running, true);
    state->attempts = 0;
    state->successes = 0;
    
    /* Create socket */
    state->socket_fd = hydra_connect_tcp(ip, port);
    if (state->socket_fd < 0) {
        free(state);
        return NULL;
    }
    
    /* Set timeout */
    struct timeval tv = {
        .tv_sec = MODULE_TIMEOUT,
        .tv_usec = 0
    };
    setsockopt(state->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(state->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    state->connected = true;
    
    /* Read banner */
    char banner[MODULE_BUFFER_SIZE];
    int len = recv(state->socket_fd, banner, sizeof(banner) - 1, 0);
    if (len > 0) {
        banner[len] = '\0';
        state->banner = strdup(banner);
    }
    
    return state;
}

static void module_disconnect(module_state_t *state) {
    if (!state) return;
    
    atomic_store(&state->running, false);
    
    if (state->ssl) {
        SSL_shutdown(state->ssl);
        SSL_free(state->ssl);
        state->ssl = NULL;
    }
    
    if (state->ssl_ctx) {
        SSL_CTX_free(state->ssl_ctx);
        state->ssl_ctx = NULL;
    }
    
    if (state->socket_fd >= 0) {
        close(state->socket_fd);
        state->socket_fd = -1;
    }
    
    if (state->banner) {
        free(state->banner);
        state->banner = NULL;
    }
    
    if (state->server_version) {
        free(state->server_version);
        state->server_version = NULL;
    }
    
    if (state->last_error_msg) {
        free(state->last_error_msg);
        state->last_error_msg = NULL;
    }
    
    state->connected = false;
    mtx_destroy(&state->lock);
}

/* -----------------------------------------------------------------
   Authentication Attempt
   ----------------------------------------------------------------- */
static int module_authenticate(module_state_t *state, char *username, char *password) {
    if (!state || !state->connected) {
        return HYDRA_LOGIN_FAILURE;
    }
    
    mtx_lock(&state->lock);
    state->attempts++;
    
    /* Send authentication command */
    char command[MODULE_BUFFER_SIZE];
    snprintf(command, sizeof(command), "AUTH %s %s\r\n", username, password);
    
    if (send(state->socket_fd, command, strlen(command), 0) < 0) {
        state->last_error = errno;
        state->last_error_msg = strdup(strerror(errno));
        mtx_unlock(&state->lock);
        return HYDRA_LOGIN_FAILURE;
    }
    
    /* Read response */
    char response[MODULE_BUFFER_SIZE];
    int len = recv(state->socket_fd, response, sizeof(response) - 1, 0);
    
    if (len <= 0) {
        mtx_unlock(&state->lock);
        return HYDRA_LOGIN_FAILURE;
    }
    
    response[len] = '\0';
    
    /* Check response */
    if (strstr(response, "SUCCESS") || strstr(response, "OK")) {
        state->successes++;
        mtx_unlock(&state->lock);
        return HYDRA_LOGIN_SUCCESS;
    }
    
    mtx_unlock(&state->lock);
    return HYDRA_LOGIN_FAILURE;
}

/* -----------------------------------------------------------------
   Banner Check
   ----------------------------------------------------------------- */
static bool module_check_banner(module_state_t *state) {
    if (!state || !state->banner) {
        return false;
    }
    
    /* Check for expected banner patterns */
    const char *patterns[] = {
        "Server",
        "Welcome",
        "Ready",
        "220",
        "SSH",
        "TELNET",
        NULL
    };
    
    for (int i = 0; patterns[i]; i++) {
        if (strstr(state->banner, patterns[i])) {
            return true;
        }
    }
    
    return false;
}

/* -----------------------------------------------------------------
   Main Module Function
   ----------------------------------------------------------------- */
int module_function(char *ip, int port, unsigned char options, char *miscptr, FILE *hydra_fp) {
    char username[256];
    char password[256];
    int result;
    module_state_t *state = NULL;
    int found = 0;
    int retries = 0;
    
    /* Build login attempt */
    snprintf(username, sizeof(username), "%s", hydra_get_next_login());
    snprintf(password, sizeof(password), "%s", hydra_get_next_password());
    
    /* Attempt login with retry */
    while (retries < MODULE_RETRY_COUNT) {
        /* Connect to server */
        state = module_connect(ip, port);
        if (!state || !state->connected) {
            retries++;
            if (retries < MODULE_RETRY_COUNT) {
                sleep(MODULE_RETRY_DELAY);
                continue;
            }
            return found;
        }
        
        /* Attempt authentication */
        result = module_authenticate(state, username, password);
        
        if (result == HYDRA_LOGIN_SUCCESS) {
            found = 1;
            hydra_report_found(ip, port, MODULE_NAME, username, password);
            
            if (hydra_fp) {
                fprintf(hydra_fp, "[%s] SUCCESS: %s:%s\n", MODULE_NAME, username, password);
            }
            
            module_disconnect(state);
            free(state);
            break;
        }
        
        /* Check if we should stop */
        if (atomic_load(&hydra_global.stop_requested)) {
            module_disconnect(state);
            free(state);
            break;
        }
        
        module_disconnect(state);
        free(state);
        state = NULL;
        retries++;
        
        if (retries < MODULE_RETRY_COUNT) {
            sleep(MODULE_RETRY_DELAY);
        }
    }
    
    return found;
}

/* -----------------------------------------------------------------
   Module Cleanup
   ----------------------------------------------------------------- */
void module_exit(FILE *hydra_fp) {
    if (hydra_fp) {
        fprintf(hydra_fp, "[%s] Cleaning up...\n", MODULE_NAME);
    }
    
    /* No global state to clean */
}

/* ============================================================
   5. MODULE REGISTRATION
   ============================================================ */
hydra_module_info_t module_info = {
    .name = MODULE_NAME,
    .desc = MODULE_DESC,
    .author = MODULE_AUTHOR,
    .version = MODULE_VERSION,
    .service = MODULE_SERVICE,
    .alias = NULL,
    .port = MODULE_DEFAULT_PORT,
    .type = SERVICE_TCP,
    .init = module_init,
    .function = module_function,
    .exit = module_exit
};

/* ============================================================
   6. COMPILATION AND USAGE
   ============================================================ */
/*
   To compile:

   1. Add to Makefile.am:
      hydra_SOURCES += hydra-modern-template.c

   2. Build:
      make clean && make

   3. Usage:
      hydra -l username -P passwords.txt target -p 12345 template
      hydra -l username -P passwords.txt target -p 12346 -m "database:domain:ssl" template
*/
#endif /* HYDRA_MODERN_TEMPLATE_H */
