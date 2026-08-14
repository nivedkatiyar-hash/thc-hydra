/*
 * hydra-nmap.c - Nmap Integration for THC-Hydra
 * 
 * This module provides:
 * - Automatic target discovery from Nmap XML output
 * - Service fingerprinting and module auto-selection
 * - Port scanning with Nmap integration
 * - Intelligent attack prioritization
 * - Real-time target discovery
 * 
 * Author: ZORG-Ω
 * License: AGPL v3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "hydra-lib.h"
#include "hydra-mod.h"

/* ============================================================
   1. DEFINITIONS
   ============================================================ */
#define NMAP_MAX_TARGETS 65536
#define NMAP_TIMEOUT 300
#define NMAP_DEFAULT_PORTS "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,5000,1433,1521,3306,5432"

/* ============================================================
   2. PORT TO SERVICE MAPPING
   ============================================================ */
typedef struct {
    int port;
    char *protocol;
    char *module;
    char *service;
} port_service_map_t;

port_service_map_t port_service_maps[] = {
    {21, "tcp", "ftp", "FTP"},
    {22, "tcp", "ssh", "SSH"},
    {23, "tcp", "telnet", "Telnet"},
    {25, "tcp", "smtp", "SMTP"},
    {53, "udp", "dns", "DNS"},
    {80, "tcp", "http", "HTTP"},
    {110, "tcp", "pop3", "POP3"},
    {111, "tcp", "rpc", "RPC"},
    {135, "tcp", "msrpc", "MSRPC"},
    {139, "tcp", "smb", "SMB"},
    {143, "tcp", "imap", "IMAP"},
    {443, "tcp", "https", "HTTPS"},
    {445, "tcp", "smb", "SMB"},
    {993, "tcp", "imap-ssl", "IMAPS"},
    {995, "tcp", "pop3-ssl", "POP3S"},
    {1433, "tcp", "mssql", "MS-SQL"},
    {1521, "tcp", "oracle", "Oracle"},
    {1723, "tcp", "pptp", "PPTP"},
    {3306, "tcp", "mysql", "MySQL"},
    {3389, "tcp", "rdp", "RDP"},
    {5000, "tcp", "sybase", "Sybase ASE"},
    {5432, "tcp", "postgres", "PostgreSQL"},
    {5900, "tcp", "vnc", "VNC"},
    {8080, "tcp", "http-proxy", "HTTP Proxy"},
    {0, NULL, NULL, NULL}
};

/* ============================================================
   3. SERVICE FINGERPRINTING
   ============================================================ */
typedef struct {
    char *banner_pattern;
    char *service_name;
    char *module_name;
    int port;
} service_fingerprint_t;

service_fingerprint_t service_fingerprints[] = {
    {"Sybase ASE", "sybase", "sybase", 5000},
    {"Sybase Adaptive Server", "sybase", "sybase", 5000},
    {"Microsoft SQL Server", "mssql", "mssql", 1433},
    {"SQL Server", "mssql", "mssql", 1433},
    {"TDS", "sybase", "sybase", 1433},
    {"MySQL", "mysql", "mysql", 3306},
    {"MariaDB", "mysql", "mysql", 3306},
    {"PostgreSQL", "postgres", "postgres", 5432},
    {"Oracle Database", "oracle", "oracle", 1521},
    {"OpenSSH", "ssh", "ssh", 22},
    {"SSH", "ssh", "ssh", 22},
    {"Telnet", "telnet", "telnet", 23},
    {"FTP", "ftp", "ftp", 21},
    {"HTTP", "http", "http", 80},
    {"HTTPS", "https", "https", 443},
    {"RDP", "rdp", "rdp", 3389},
    {"VNC", "vnc", "vnc", 5900},
    {"SMB", "smb", "smb", 445},
    {NULL, NULL, NULL, 0}
};

/* ============================================================
   4. NMAP TARGET STRUCTURE
   ============================================================ */
typedef struct {
    char *ip;
    int port;
    char *protocol;
    char *service;
    char *module;
    char *state;
    char *banner;
    int priority;
    time_t timestamp;
} nmap_target_t;

typedef struct {
    nmap_target_t *targets;
    int count;
    int max_count;
    char *current_target_file;
} nmap_target_list_t;

static nmap_target_list_t target_list;

/* ============================================================
   5. XML PARSING FUNCTIONS
   ============================================================ */
int parse_nmap_xml(const char *filename, nmap_target_list_t *list) {
    if (!filename || !list) return -1;
    
    xmlDocPtr doc = xmlParseFile(filename);
    if (!doc) {
        fprintf(stderr, "Error: Could not parse Nmap XML file %s\n", filename);
        return -1;
    }
    
    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (!xpathCtx) {
        xmlFreeDoc(doc);
        return -1;
    }
    
    /* Query for all hosts */
    xmlXPathObjectPtr hostObj = xmlXPathEvalExpression(BAD_CAST "//host", xpathCtx);
    if (!hostObj || xmlXPathNodeSetIsEmpty(hostObj->nodesetval)) {
        xmlXPathFreeObject(hostObj);
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return 0;
    }
    
    xmlNodeSetPtr hosts = hostObj->nodesetval;
    int count = 0;
    
    for (int i = 0; i < hosts->nodeNr; i++) {
        xmlNodePtr host = hosts->nodeTab[i];
        
        /* Get IP address */
        xmlXPathObjectPtr ipObj = xmlXPathEvalExpression(BAD_CAST "address[@addrtype='ipv4']/@addr", xpathCtx);
        if (!ipObj || xmlXPathNodeSetIsEmpty(ipObj->nodesetval)) {
            xmlXPathFreeObject(ipObj);
            continue;
        }
        
        xmlChar *ip = xmlXPathCastNodeToString(ipObj->nodesetval->nodeTab[0]);
        xmlXPathFreeObject(ipObj);
        
        /* Get ports */
        xmlXPathObjectPtr portObj = xmlXPathEvalExpression(BAD_CAST ".//port", xpathCtx);
        if (portObj && !xmlXPathNodeSetIsEmpty(portObj->nodesetval)) {
            xmlNodeSetPtr ports = portObj->nodesetval;
            
            for (int j = 0; j < ports->nodeNr; j++) {
                xmlNodePtr port = ports->nodeTab[j];
                
                /* Get port ID */
                xmlChar *portId = xmlGetProp(port, BAD_CAST "portid");
                if (!portId) continue;
                
                /* Get protocol */
                xmlChar *protocol = xmlGetProp(port, BAD_CAST "protocol");
                if (!protocol) {
                    xmlFree(portId);
                    continue;
                }
                
                /* Check if port is open */
                xmlXPathObjectPtr stateObj = xmlXPathEvalExpression(BAD_CAST ".//state", xpathCtx);
                if (stateObj && !xmlXPathNodeSetIsEmpty(stateObj->nodesetval)) {
                    xmlNodePtr state = stateObj->nodesetval->nodeTab[0];
                    xmlChar *stateVal = xmlGetProp(state, BAD_CAST "state");
                    
                    if (stateVal && xmlStrEqual(stateVal, BAD_CAST "open")) {
                        /* Add target */
                        if (list->count < list->max_count) {
                            nmap_target_t *target = &list->targets[list->count];
                            target->ip = strdup((char *)ip);
                            target->port = atoi((char *)portId);
                            target->protocol = protocol ? strdup((char *)protocol) : strdup("tcp");
                            target->state = strdup("open");
                            
                            /* Try to map port to service */
                            target->service = NULL;
                            target->module = NULL;
                            
                            for (int k = 0; port_service_maps[k].port; k++) {
                                if (port_service_maps[k].port == target->port) {
                                    target->service = strdup(port_service_maps[k].service);
                                    target->module = strdup(port_service_maps[k].module);
                                    break;
                                }
                            }
                            
                            target->priority = 5;
                            target->timestamp = time(NULL);
                            list->count++;
                            
                            if (list->count >= list->max_count) {
                                xmlFree(stateVal);
                                xmlFree(stateObj);
                                break;
                            }
                        }
                        xmlFree(stateVal);
                    }
                    xmlFreeXPathObject(stateObj);
                }
                
                xmlFree(portId);
                if (protocol) xmlFree(protocol);
            }
            xmlXPathFreeObject(portObj);
        }
        
        xmlFree(ip);
    }
    
    xmlXPathFreeObject(hostObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    
    return count;
}

/* ============================================================
   6. NMAP SCANNER FUNCTIONS
   ============================================================ */
int run_nmap_scan(char *target, char *ports, char *output_file) {
    if (!target) return -1;
    
    char command[4096];
    char temp_file[256];
    
    if (!output_file) {
        snprintf(temp_file, sizeof(temp_file), "/tmp/hydra_nmap_%d.xml", getpid());
        output_file = temp_file;
    }
    
    if (!ports || strlen(ports) == 0) {
        ports = NMAP_DEFAULT_PORTS;
    }
    
    /* Build nmap command */
    snprintf(command, sizeof(command),
        "nmap -sS -sV -p %s -oX %s --open --host-timeout 30s %s",
        ports, output_file, target);
    
    printf("[NMAP] Running: %s\n", command);
    
    /* Execute nmap */
    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "[NMAP] Nmap scan failed with code %d\n", ret);
        return -1;
    }
    
    /* Parse output */
    return parse_nmap_xml(output_file, &target_list);
}

/* ============================================================
   7. TARGET PRIORITIZATION
   ============================================================ */
void prioritize_targets(nmap_target_list_t *list) {
    if (!list || list->count == 0) return;
    
    /* Sort by priority (higher priority first) */
    for (int i = 0; i < list->count - 1; i++) {
        for (int j = i + 1; j < list->count; j++) {
            if (list->targets[i].priority < list->targets[j].priority) {
                nmap_target_t temp = list->targets[i];
                list->targets[i] = list->targets[j];
                list->targets[j] = temp;
            }
        }
    }
}

void set_target_priority(nmap_target_t *target) {
    if (!target) return;
    
    /* Higher priority for common services */
    if (strcmp(target->module, "ssh") == 0) target->priority = 10;
    else if (strcmp(target->module, "ftp") == 0) target->priority = 9;
    else if (strcmp(target->module, "sybase") == 0) target->priority = 8;
    else if (strcmp(target->module, "mssql") == 0) target->priority = 8;
    else if (strcmp(target->module, "mysql") == 0) target->priority = 7;
    else if (strcmp(target->module, "postgres") == 0) target->priority = 7;
    else if (strcmp(target->module, "http") == 0) target->priority = 6;
    else if (strcmp(target->module, "https") == 0) target->priority = 6;
    else target->priority = 5;
}

/* ============================================================
   8. MODULE AUTOSELECTION
   ============================================================ */
char *detect_module_from_banner(char *banner) {
    if (!banner) return NULL;
    
    for (int i = 0; service_fingerprints[i].banner_pattern; i++) {
        if (strstr(banner, service_fingerprints[i].banner_pattern)) {
            return service_fingerprints[i].module_name;
        }
    }
    return NULL;
}

char *auto_select_module(char *host, int port, char *banner) {
    /* Try banner detection first */
    char *module = detect_module_from_banner(banner);
    if (module) return module;
    
    /* Fall back to port mapping */
    for (int i = 0; port_service_maps[i].port; i++) {
        if (port_service_maps[i].port == port) {
            return port_service_maps[i].module;
        }
    }
    
    return NULL;
}

/* ============================================================
   9. TARGET GENERATION FUNCTIONS
   ============================================================ */
nmap_target_t *get_next_target(nmap_target_list_t *list) {
    if (!list || list->count == 0) return NULL;
    
    static int current_index = 0;
    if (current_index >= list->count) {
        current_index = 0;
        return NULL;
    }
    
    return &list->targets[current_index++];
}

void reset_target_iteration(nmap_target_list_t *list) {
    if (!list) return;
    list->count = 0;
    // Note: targets are not freed here to avoid double free
}

/* ============================================================
   10. NMAP INTEGRATION INITIALIZATION
   ============================================================ */
int nmap_init(void) {
    /* Initialize target list */
    target_list.max_count = NMAP_MAX_TARGETS;
    target_list.targets = calloc(target_list.max_count, sizeof(nmap_target_t));
    if (!target_list.targets) {
        fprintf(stderr, "Error: Cannot allocate memory for target list\n");
        return -1;
    }
    target_list.count = 0;
    target_list.current_target_file = NULL;
    
    /* Initialize libxml */
    xmlInitParser();
    LIBXML_TEST_VERSION
    
    return 0;
}

void nmap_cleanup(void) {
    /* Clean up targets */
    for (int i = 0; i < target_list.count; i++) {
        if (target_list.targets[i].ip) free(target_list.targets[i].ip);
        if (target_list.targets[i].protocol) free(target_list.targets[i].protocol);
        if (target_list.targets[i].service) free(target_list.targets[i].service);
        if (target_list.targets[i].module) free(target_list.targets[i].module);
        if (target_list.targets[i].state) free(target_list.targets[i].state);
        if (target_list.targets[i].banner) free(target_list.targets[i].banner);
    }
    free(target_list.targets);
    target_list.targets = NULL;
    target_list.count = 0;
    
    /* Cleanup libxml */
    xmlCleanupParser();
}

/* ============================================================
   11. COMMAND LINE INTERFACE
   ============================================================ */
void nmap_print_targets(nmap_target_list_t *list) {
    if (!list || list->count == 0) {
        printf("[NMAP] No targets found\n");
        return;
    }
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    NMAP TARGETS                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ %-15s %-8s %-10s %-8s %-10s ║\n", 
           "IP", "Port", "Protocol", "Module", "Priority");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    
    for (int i = 0; i < list->count && i < 50; i++) {
        nmap_target_t *t = &list->targets[i];
        printf("║ %-15s %-8d %-10s %-8s %-10d ║\n",
               t->ip ? t->ip : "N/A",
               t->port,
               t->protocol ? t->protocol : "N/A",
               t->module ? t->module : "auto",
               t->priority);
    }
    
    if (list->count > 50) {
        printf("║ ... and %d more targets                                    ║\n", list->count - 50);
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("Total targets: %d\n", list->count);
}

/* ============================================================
   12. MAIN INTEGRATION FUNCTION
   ============================================================ */
int hydra_nmap_integration(int argc, char **argv, hydra_options_t *opts) {
    if (!opts) return -1;
    
    printf("[NMAP] Initializing...\n");
    if (nmap_init() != 0) {
        return -1;
    }
    
    char *target = NULL;
    char *ports = NULL;
    char *output_file = NULL;
    int scan_only = 0;
    
    /* Parse nmap-specific arguments */
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--nmap-target") == 0 && i + 1 < argc) {
            target = argv[++i];
        } else if (strcmp(argv[i], "--nmap-ports") == 0 && i + 1 < argc) {
            ports = argv[++i];
        } else if (strcmp(argv[i], "--nmap-output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--nmap-scan-only") == 0) {
            scan_only = 1;
        }
    }
    
    if (!target) {
        fprintf(stderr, "[NMAP] Error: No target specified (--nmap-target)\n");
        nmap_cleanup();
        return -1;
    }
    
    printf("[NMAP] Scanning %s...\n", target);
    int count = run_nmap_scan(target, ports, output_file);
    
    if (count > 0) {
        printf("[NMAP] Found %d targets\n", count);
        prioritize_targets(&target_list);
        nmap_print_targets(&target_list);
        
        if (scan_only) {
            nmap_cleanup();
            return 0;
        }
        
        /* Generate hydra command for each target */
        printf("\n[NMAP] Generating Hydra commands:\n");
        for (int i = 0; i < target_list.count; i++) {
            nmap_target_t *t = &target_list.targets[i];
            char *module = t->module;
            if (!module) {
                module = auto_select_module(t->ip, t->port, t->banner);
            }
            
            if (module) {
                printf("  hydra -l admin -P passwords.txt %s -p %d %s\n",
                       t->ip, t->port, module);
            }
        }
    } else {
        printf("[NMAP] No open ports found\n");
    }
    
    nmap_cleanup();
    return count;
}

/* ============================================================
   13. BANNER GRABBING FUNCTION
   ============================================================ */
char *grab_banner(char *host, int port, int timeout) {
    if (!host) return NULL;
    
    int sock = hydra_connect_tcp(host, port);
    if (sock < 0) return NULL;
    
    /* Send a probe */
    char probe[] = "\r\n";
    send(sock, probe, strlen(probe), 0);
    
    /* Receive banner */
    char buffer[4096];
    int len = recv(sock, buffer, sizeof(buffer) - 1, timeout);
    if (len > 0) {
        buffer[len] = '\0';
        
        /* Clean up banner */
        for (int i = 0; i < len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = ' ';
            }
        }
        
        close(sock);
        return strdup(buffer);
    }
    
    close(sock);
    return NULL;
}

/* ============================================================
   14. SERVICE DETECTION WITH BANNER
   ============================================================ */
char *detect_service_with_banner(char *host, int port) {
    char *banner = grab_banner(host, port, 5);
    if (!banner) return NULL;
    
    char *service = NULL;
    for (int i = 0; service_fingerprints[i].banner_pattern; i++) {
        if (strstr(banner, service_fingerprints[i].banner_pattern)) {
            service = service_fingerprints[i].service_name;
            break;
        }
    }
    
    free(banner);
    return service;
}

/* ============================================================
   15. COMPLETE AUTO-CRACK MODULE
   ============================================================ */
int hydra_auto_crack(char *target, char *userlist, char *passlist) {
    printf("[AUTO] Starting automatic cracking for %s\n", target);
    
    nmap_init();
    run_nmap_scan(target, NULL, NULL);
    
    printf("\n[AUTO] Found %d targets\n", target_list.count);
    
    int success_count = 0;
    for (int i = 0; i < target_list.count; i++) {
        nmap_target_t *t = &target_list.targets[i];
        char *module = t->module;
        
        if (!module) {
            module = detect_module_from_banner(t->banner);
            if (!module) {
                module = auto_select_module(t->ip, t->port, t->banner);
            }
        }
        
        if (!module) {
            printf("[AUTO] Skipping %s:%d (unknown service)\n", t->ip, t->port);
            continue;
        }
        
        printf("[AUTO] Attacking %s:%d with %s\n", t->ip, t->port, module);
        
        /* Build and execute hydra command */
        char command[1024];
        snprintf(command, sizeof(command),
            "hydra -l %s -P %s %s -p %d %s",
            userlist ? userlist : "admin",
            passlist ? passlist : "passwords.txt",
            t->ip, t->port, module);
        
        printf("[AUTO] Running: %s\n", command);
        int ret = system(command);
        if (ret == 0) success_count++;
    }
    
    printf("[AUTO] Completed. %d successful cracks\n", success_count);
    nmap_cleanup();
    return success_count;
}

/* ============================================================
   16. TEST FUNCTION
   ============================================================ */
#ifdef TEST_NMAP
int main(int argc, char **argv) {
    printf("ZORG-Ω Nmap Integration Test\n");
    printf("============================\n\n");
    
    char *target = "127.0.0.1";
    if (argc > 1) target = argv[1];
    
    printf("Testing with target: %s\n", target);
    printf("Service detection: %s\n", detect_service_with_banner(target, 22));
    printf("Service detection: %s\n", detect_service_with_banner(target, 80));
    printf("Service detection: %s\n", detect_service_with_banner(target, 5000));
    
    /* Test port mapping */
    for (int i = 0; port_service_maps[i].port; i++) {
        printf("Port %d -> Module: %s\n", 
               port_service_maps[i].port, 
               port_service_maps[i].module);
    }
    
    return 0;
}
#endif
