/*
 * hydra-sybase.c - Sybase TDS password cracker module for THC-Hydra
 * 
 * This module implements Sybase ASE (Adaptive Server Enterprise) and 
 * MS-SQL Server authentication cracking using the FreeTDS library.
 * 
 * Author: ZORG-Ω (Theoretical Implementation)
 * License: AGPL v3
 * 
 * Based on hydra-mssql.c and FreeTDS documentation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <tds.h>
#include <sybdb.h>
#include <sybfront.h>

#include "hydra-mod.h"

#ifndef HAVE_SYBASE
#error "Sybase support not compiled. Please install FreeTDS (libsybdb-dev) and recompile."
#endif

/* ============================================================
   1. MODULE DEFINITIONS
   ============================================================ */
#define MODULE_NAME "sybase"
#define MODULE_DESC "Sybase ASE / MS-SQL Server (TDS) password cracker"
#define MODULE_AUTHOR "ZORG-Ω"
#define MODULE_VERSION "1.0.0"
#define MODULE_SERVICE "sybase"
#define MODULE_ALIAS "mssql-tds"

#define SYBASE_DEFAULT_PORT 5000
#define SYBASE_SSL_PORT 5001
#define TIMEOUT 30
#define MAX_RETRIES 3
#define BUFFER_SIZE 4096

/* ============================================================
   2. MODULE STRUCTURE
   ============================================================ */
typedef struct {
    int socket_fd;
    LOGINREC *login;
    DBPROCESS *dbproc;
    int connected;
    int ssl_enabled;
    char *server;
    int port;
    char *database;
    char *domain;
    int timeout;
} sybase_connection_t;

/* ============================================================
   3. GLOBAL VARIABLES
   ============================================================ */
static int module_initialized = 0;
static char *target_host = NULL;
static int target_port = SYBASE_DEFAULT_PORT;
static char *database_name = NULL;
static char *domain_name = NULL;
static int use_ssl = 0;
static int verbose = 0;

/* ============================================================
   4. MODULE INITIALIZATION
   ============================================================ */
int hydra_module_info(char *service_name, char *service_desc, char *service_author, 
                       char *service_version, unsigned int *service_type) {
    strcpy(service_name, MODULE_NAME);
    strcpy(service_desc, MODULE_DESC);
    strcpy(service_author, MODULE_AUTHOR);
    strcpy(service_version, MODULE_VERSION);
    *service_type = SERVICE_TCP;
    return 1;
}

int hydra_module_init(char *ip, int port, unsigned char options, char *miscptr, FILE *hydra_fp) {
    char *ptr;
    
    /* Store target information */
    target_host = strdup(ip);
    target_port = port ? port : SYBASE_DEFAULT_PORT;
    
    /* Parse miscptr for options */
    if (miscptr) {
        /* Format: database:domain:ssl */
        char *tokens[3];
        int token_count = 0;
        char *saveptr;
        char *misc_copy = strdup(miscptr);
        
        ptr = strtok_r(misc_copy, ":", &saveptr);
        while (ptr && token_count < 3) {
            tokens[token_count++] = ptr;
            ptr = strtok_r(NULL, ":", &saveptr);
        }
        
        if (token_count > 0 && strlen(tokens[0]) > 0) {
            database_name = strdup(tokens[0]);
        }
        if (token_count > 1 && strlen(tokens[1]) > 0) {
            domain_name = strdup(tokens[1]);
        }
        if (token_count > 2 && strcmp(tokens[2], "ssl") == 0) {
            use_ssl = 1;
            if (target_port == SYBASE_DEFAULT_PORT) {
                target_port = SYBASE_SSL_PORT;
            }
        }
        
        free(misc_copy);
    }
    
    /* Initialize FreeTDS */
    if (!module_initialized) {
        dbinit();
        module_initialized = 1;
    }
    
    /* Check if we can connect to the server */
    sybase_connection_t *conn = sybase_connect();
    if (!conn || !conn->connected) {
        if (hydra_fp) {
            fprintf(hydra_fp, "[%s] Could not connect to Sybase server on %s:%d\n", 
                    MODULE_NAME, ip, target_port);
        }
        if (conn) {
            if (conn->login) dbloginfree(conn->login);
            free(conn);
        }
        return 0;
    }
    
    /* Clean up test connection */
    if (conn->dbproc) dbclose(conn->dbproc);
    if (conn->login) dbloginfree(conn->login);
    free(conn);
    
    if (hydra_fp) {
        fprintf(hydra_fp, "[%s] Sybase server found on %s:%d\n", 
                MODULE_NAME, ip, target_port);
    }
    
    return 1;
}

/* ============================================================
   5. CONNECTION MANAGEMENT
   ============================================================ */
sybase_connection_t *sybase_connect() {
    sybase_connection_t *conn = calloc(1, sizeof(sybase_connection_t));
    if (!conn) return NULL;
    
    conn->server = target_host;
    conn->port = target_port;
    conn->timeout = TIMEOUT;
    conn->ssl_enabled = use_ssl;
    conn->connected = 0;
    
    /* Create login structure */
    conn->login = dblogin();
    if (!conn->login) {
        free(conn);
        return NULL;
    }
    
    /* Set login parameters */
    DBSETLUSER(conn->login, "");
    DBSETLPWD(conn->login, "");
    DBSETLAPP(conn->login, "hydra");
    DBSETLHOST(conn->login, "hydra-client");
    
    /* Set timeout */
    DBSETLTIME(conn->login, TIMEOUT);
    
    /* Set database if specified */
    if (database_name) {
        DBSETLDB(conn->login, database_name);
    }
    
    /* Set domain if specified */
    if (domain_name) {
        /* Sybase doesn't have domain auth, but we can use it for other purposes */
        /* For MS-SQL, this could be used for NTLM authentication */
    }
    
    /* Set SSL if enabled */
    if (use_ssl) {
        DBSETLENCRYPT(conn->login, TRUE);
        DBSETLTRUSTED(conn->login, TRUE);
    }
    
    /* Connect to server */
    conn->dbproc = dbopen(conn->login, conn->server);
    if (!conn->dbproc) {
        char *error = NULL;
        dberrstr(&error);
        if (verbose) {
            fprintf(stderr, "[%s] dbopen failed: %s\n", MODULE_NAME, error ? error : "unknown");
        }
        if (conn->login) dbloginfree(conn->login);
        free(conn);
        return NULL;
    }
    
    /* Check connection */
    if (dbuse(conn->dbproc, database_name ? database_name : "master") == FAIL) {
        char *error = NULL;
        dberrstr(&error);
        if (verbose) {
            fprintf(stderr, "[%s] dbuse failed: %s\n", MODULE_NAME, error ? error : "unknown");
        }
        dbclose(conn->dbproc);
        if (conn->login) dbloginfree(conn->login);
        free(conn);
        return NULL;
    }
    
    conn->connected = 1;
    return conn;
}

void sybase_disconnect(sybase_connection_t *conn) {
    if (!conn) return;
    
    if (conn->dbproc) {
        dbclose(conn->dbproc);
        conn->dbproc = NULL;
    }
    
    if (conn->login) {
        dbloginfree(conn->login);
        conn->login = NULL;
    }
    
    conn->connected = 0;
    free(conn);
}

/* ============================================================
   6. AUTHENTICATION ATTEMPT
   ============================================================ */
int sybase_attempt_login(char *username, char *password, sybase_connection_t **conn_out) {
    sybase_connection_t *conn = NULL;
    int result = HYDRA_LOGIN_FAILURE;
    int retries = 0;
    
    while (retries < MAX_RETRIES) {
        /* Connect to server */
        conn = sybase_connect();
        if (!conn || !conn->connected) {
            retries++;
            if (retries < MAX_RETRIES) {
                usleep(1000000); /* Wait 1 second before retry */
                continue;
            }
            return HYDRA_LOGIN_FAILURE;
        }
        
        /* Set credentials */
        DBSETLUSER(conn->login, username);
        DBSETLPWD(conn->login, password);
        
        /* Try to reconnect with new credentials */
        if (dbopen(conn->login, conn->server)) {
            /* Login successful */
            result = HYDRA_LOGIN_SUCCESS;
            break;
        }
        
        /* Login failed */
        char *error = NULL;
        dberrstr(&error);
        
        /* Check if it's a password error or other issue */
        if (error) {
            if (strstr(error, "Login failed") || 
                strstr(error, "Invalid password") ||
                strstr(error, "Incorrect password")) {
                /* Password incorrect - stop retrying */
                sybase_disconnect(conn);
                conn = NULL;
                result = HYDRA_LOGIN_FAILURE;
                break;
            }
        }
        
        /* Connection error - retry */
        sybase_disconnect(conn);
        conn = NULL;
        retries++;
        
        if (retries < MAX_RETRIES) {
            usleep(1000000);
        } else {
            result = HYDRA_LOGIN_FAILURE;
        }
    }
    
    /* Store connection for successful login */
    if (result == HYDRA_LOGIN_SUCCESS && conn_out) {
        *conn_out = conn;
    } else if (conn) {
        sybase_disconnect(conn);
    }
    
    return result;
}

/* ============================================================
   7. MAIN MODULE FUNCTION
   ============================================================ */
int hydra_module_function(char *ip, int port, unsigned char options, 
                           char *miscptr, FILE *hydra_fp) {
    char username[256];
    char password[256];
    int result;
    sybase_connection_t *conn = NULL;
    int found = 0;
    
    /* Reuse initialized data */
    if (target_host && strcmp(target_host, ip) != 0) {
        free(target_host);
        target_host = strdup(ip);
    }
    
    if (port != target_port) {
        target_port = port;
    }
    
    /* Build login attempt */
    snprintf(username, sizeof(username), "%s", hydra_get_next_login());
    snprintf(password, sizeof(password), "%s", hydra_get_next_password());
    
    /* Try to login */
    result = sybase_attempt_login(username, password, &conn);
    
    if (result == HYDRA_LOGIN_SUCCESS) {
        /* Found valid credentials */
        found = 1;
        hydra_report_found(host, port, MODULE_NAME, username, password);
        
        /* Display additional info from the connection */
        if (conn && conn->dbproc) {
            char *server_name = NULL;
            char *server_version = NULL;
            
            /* Get server information */
            if (dbwritetext(conn->dbproc, "SELECT @@SERVERNAME", 0) == SUCCEED) {
                char result_buffer[1024];
                DBBUFFER dbuffer;
                dbcursorbind(conn->dbproc, &dbuffer);
                while (dbnextrow(conn->dbproc) != NO_MORE_ROWS) {
                    dbconvert(NULL, 0, dbdata(conn->dbproc, 1), dbdatlen(conn->dbproc, 1), 
                             SYBCHAR, result_buffer, sizeof(result_buffer));
                    if (verbose) {
                        fprintf(hydra_fp, "[%s] Server name: %s\n", MODULE_NAME, result_buffer);
                    }
                }
            }
        }
        
        sybase_disconnect(conn);
        return found;
    }
    
    /* Login failed */
    if (conn) {
        sybase_disconnect(conn);
    }
    
    /* Check if we should stop */
    if (hydra_stop_check()) {
        return found;
    }
    
    return found;
}

/* ============================================================
   8. MODULE CLEANUP
   ============================================================ */
void hydra_module_exit(FILE *hydra_fp) {
    if (target_host) {
        free(target_host);
        target_host = NULL;
    }
    if (database_name) {
        free(database_name);
        database_name = NULL;
    }
    if (domain_name) {
        free(domain_name);
        domain_name = NULL;
    }
    
    /* Clean up FreeTDS */
    if (module_initialized) {
        dbexit();
        module_initialized = 0;
    }
}

/* ============================================================
   9. ERROR HANDLING
   ============================================================ */
void sybase_error_handler(DBPROCESS *dbproc, int severity, int dberr, int oserr, 
                          char *dberrstr, char *oserrstr) {
    if (verbose) {
        fprintf(stderr, "[%s] FreeTDS Error: %s\n", MODULE_NAME, dberrstr);
        if (oserrstr && strlen(oserrstr) > 0) {
            fprintf(stderr, "[%s] OS Error: %s\n", MODULE_NAME, oserrstr);
        }
    }
}

void sybase_message_handler(DBPROCESS *dbproc, char *msg, int msgtype) {
    if (verbose && msgtype == 0) {
        fprintf(stderr, "[%s] Server Message: %s\n", MODULE_NAME, msg);
    }
}

/* ============================================================
   10. OPTIONAL: ADVANCED FEATURES
   ============================================================ */

/* Support for NTLM authentication (MS-SQL specific) */
int sybase_ntlm_login(char *username, char *password, char *domain) {
    sybase_connection_t *conn = NULL;
    int result = HYDRA_LOGIN_FAILURE;
    
    conn = sybase_connect();
    if (!conn || !conn->connected) {
        return HYDRA_LOGIN_FAILURE;
    }
    
    /* Set NTLM authentication for MS-SQL */
    DBSETLUSER(conn->login, username);
    DBSETLPWD(conn->login, password);
    
    if (domain && strlen(domain) > 0) {
        /* For MS-SQL, this could set the domain */
        DBSETLAPP(conn->login, domain);
    }
    
    /* Try to connect */
    if (dbopen(conn->login, conn->server)) {
        result = HYDRA_LOGIN_SUCCESS;
    }
    
    sybase_disconnect(conn);
    return result;
}

/* Support for database enumeration */
int sybase_enumerate_databases(char *username, char *password, FILE *hydra_fp) {
    sybase_connection_t *conn = NULL;
    int result = 0;
    
    conn = sybase_connect();
    if (!conn || !conn->connected) {
        return 0;
    }
    
    /* Set credentials */
    DBSETLUSER(conn->login, username);
    DBSETLPWD(conn->login, password);
    
    if (dbopen(conn->login, conn->server)) {
        /* Query databases */
        DBCHAR *query = "SELECT name FROM sysdatabases WHERE dbid > 4";
        if (dbwritetext(conn->dbproc, query, 0) == SUCCEED) {
            char result_buffer[256];
            DBBUFFER dbuffer;
            dbcursorbind(conn->dbproc, &dbuffer);
            
            while (dbnextrow(conn->dbproc) != NO_MORE_ROWS) {
                dbconvert(NULL, 0, dbdata(conn->dbproc, 1), dbdatlen(conn->dbproc, 1),
                         SYBCHAR, result_buffer, sizeof(result_buffer));
                if (hydra_fp) {
                    fprintf(hydra_fp, "[%s] Database: %s\n", MODULE_NAME, result_buffer);
                }
                result++;
            }
        }
    }
    
    sybase_disconnect(conn);
    return result;
}

/* ============================================================
   11. MODULE INFORMATION FOR HYDRACORE
   ============================================================ */
hydra_module_info_t module_info = {
    .name = MODULE_NAME,
    .desc = MODULE_DESC,
    .author = MODULE_AUTHOR,
    .version = MODULE_VERSION,
    .service = MODULE_SERVICE,
    .alias = MODULE_ALIAS,
    .port = SYBASE_DEFAULT_PORT,
    .type = SERVICE_TCP,
    .init = hydra_module_init,
    .function = hydra_module_function,
    .exit = hydra_module_exit
};

/* ============================================================
   12. COMPILATION INSTRUCTIONS
   ============================================================ */
/*
   To compile this module:

   1. Install FreeTDS:
      Ubuntu/Debian: sudo apt-get install libsybdb-dev freetds-dev
      RHEL/CentOS: sudo yum install freetds freetds-devel
      macOS: brew install freetds

   2. In hydra's configure.ac, add:
      AC_CHECK_HEADER(sybdb.h, [HAVE_SYBASE=1])
      AC_CHECK_LIB(sybdb, dbinit, [SYBASE_LIBS="-lsybdb"], [SYBASE_LIBS=""])

   3. Update Makefile.am:
      hydra_SOURCES = hydra-sybase.c
      hydra_LDADD = -lsybdb $(SYBASE_LIBS)

   4. Rebuild hydra:
      ./configure --with-sybase
      make clean
      make

   5. Run:
      hydra -l username -P passwords.txt target -s 5000 sybase
      hydra -l username -P passwords.txt target sybase
      hydra -l username -P passwords.txt target -s 1433 mssql-tds
*/

/* ============================================================
   13. USAGE EXAMPLES
   ============================================================ */
/*
   Basic Sybase cracking:
   hydra -l sa -P passwords.txt 192.168.1.100 sybase

   Sybase with specific database:
   hydra -l sa -P passwords.txt 192.168.1.100 -m "mydb" sybase

   Sybase with SSL:
   hydra -l sa -P passwords.txt 192.168.1.100 -p 5001 -m "master::ssl" sybase

   MS-SQL via TDS:
   hydra -l sa -P passwords.txt 192.168.1.100 -p 1433 mssql-tds

   MS-SQL with NTLM domain:
   hydra -l sa -P passwords.txt 192.168.1.100 -m "master::domain" mssql-tds

   Enumerate databases after cracking:
   hydra -l sa -P passwords.txt 192.168.1.100 -v sybase
*/

/* ============================================================
   14. TESTING & DEBUGGING
   ============================================================ */
#ifdef TEST_MODE
int main(int argc, char **argv) {
    /* Test the module standalone */
    FILE *test_fp = stdout;
    char *ip = "192.168.1.100";
    int port = 5000;
    
    printf("Testing Sybase module...\n");
    
    /* Initialize module */
    if (!hydra_module_init(ip, port, 0, "master::", test_fp)) {
        printf("Failed to initialize module\n");
        return 1;
    }
    
    /* Test login */
    char *test_username = "sa";
    char *test_password = "password123";
    
    printf("Testing credentials: %s:%s\n", test_username, test_password);
    
    sybase_connection_t *conn = NULL;
    int result = sybase_attempt_login(test_username, test_password, &conn);
    
    if (result == HYDRA_LOGIN_SUCCESS) {
        printf("Login successful!\n");
        if (conn) {
            sybase_disconnect(conn);
        }
    } else {
        printf("Login failed.\n");
    }
    
    /* Clean up */
    hydra_module_exit(test_fp);
    
    return 0;
}
#endif
