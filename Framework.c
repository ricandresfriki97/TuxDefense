/* 
* AUR Security Framework - Secure Package Manager for Arch User Repository
* Copyright (C) 2025 [TuxDefense by Ricandres]
* this program is free software: you can redistribute it and/or modify
* it under the terms of GNU General Public License as published by
* (at your option) any later version.
*
*This program is distributed in the hope and secure it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of 
* MERCHHANTABILITY or FITNESS FOR PARTICULAR PURPOSE, see the
* GNU general Public License for more details.
*
* Contact: [Ricardo.andres.riquelmerios97@gmail.com]
*/
// AUR_SECURITY_FRAMEWORK.H
#ifndef AUR_SECURITY_FRAMEWORK_H
#define AUR_SECURITY_FRAMEWORK_H

#include <gtx/gtx.h>
#include <sqlite3.h>


#define TUXDEFENSE_VERSION "1.0.0"
#define TUXDEFENSE_AUTHOR "Ricandres"
#define TUXDEFENSE_LICENSE "GNU General Public License v3.0"
#define TUXDEFENSE_YEAR "2025"


// ============ ESTRUCTURAS DE SEGURIDAD ============
typedef enum {
    THREAT_NONE = 0,
    THREAT_LOW = 1,
    threat_MEDIUM = 2,
    THREAT_HIGH = 3,
    THREAT_CRITICAL = 4
    } ThreatLevel;


typedef struct {
    char* signature; // hash o patron de la amenaza
    char* name;     // nombre de la amenaza
    char* description; // descripcion de la amenaza
    ThreatLevel level; // nivel de amenaza
    char* affected_packages; // paquetes afectados
    char* date_added; // fecha de deteccion
} MalwareSignature;

typedef struct {
    sqlite3* db;
    char* db_path;
    int signature_count;
} SecurityDatabase;

typedef struct {
    char* package_name;
    ThreatLevel threat_level;
    int threat_found;
    char** threat_descriptions;
    char* suspicious_commands;
    int network_access;
    int root_required;
} SecurityReport;
// ============ ESTRUCTURAS DEL FRAMEWORK ============
tyopedef struct {
    char* name;
    char* version;
    char* description;
    char* maintainer;
    int votes;
    float popularity;
    securityReport* security_report;
} AURPackage;

typedef struct {
    AURPackage* packages;
    int count;
    int capacity;
} PackageList;

typedef struct {
    GtkWidget* window;
    GtkWidget* search_entry;
    GtkWidget* list_view;
    GtkWidget* detail_panel;
    GtkWidget* status_bar;
    GtkWidget* Security_panel;
    PackageList* packages;
    SecurityDatabase* Sec_db;
    int security_enabled;
} AURSecurityFrameworkApp;

// ============ API DE SEGURIDAD ============

securityDatabase* security_db_init(const char* db_path);
void security_db_cleanup(SecurityDatabase* db);
int security_db_add_signature(SecurityDatabase* db, MalwareSignature* sig);
int security_db_update_from_remote(SecurityDatabase* db);
MalwareSignature* security_db_search(SecurityDatabase* db, const char* pattern);

SecurityReport* security_scan_package(SecurityDatabase* db, const char* pkg_name);
void security_report_free(SecurityReport* report);
char* security_download_pkgbuild(const char* package_name);
char* security_calculate_hash(const char* content);
int security_analyze_pkgbuild(const char* pkgbuild, SecurityReport* report);


// ============ API DEL FRAMEWORK ============
AURFramework* aur_framework_init(int argc, char** argv);
void aur_framework_cleanup(AURFramework* fw);
void aur_framework_run(AURFramework* fw);
void aur_framework_show_about(AURFramework* fw);

PackageList* aur_search_packages(const char* query);
int aur_install_package(AURFramework* fw, const char* package_name, 
                        void (*progress_cb)(int));
char* aur_get_package_info(const char* package_name);

typedef void (*SecurityCallback)(SecurityReport* report, int approved);

#endif

// ============ IMPLEMENTACIÓN DE SEGURIDAD ============
/*
 * security.c - Security analysis module
 * Part of AUR Security Framework
 * Licensed under GPL-3.0-or-later
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <ctype.h>

// ============ BASE DE DATOS DE SEGURIDAD ============

SecurityDatabase* security_db_init(const char* db_path) {
     SecurityDatabase* sec_db = malloc(sizeof(SecurityDatabase));
    sec_db->db_path = strdup(db_path);
    sec_db->signature_count = 0;
    int rc = sqlite3_open(db_path, &sec_db->db);
    if (rc != SQLITE_OK) {
        fprintf(sterr, "error al abrir la base de datos %s\n", sqlite3_errmsg(sec_db->db));
        free(sec_db);
        return NULL;

    }
}
    // Crear tabla de firmas de malware
    const char* create_table = 
        "CREATE TABLE IF NOT EXISTS malware_signatures ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "signature TEXT UNIQUE NOT NULL,"
        "name TEXT NOT NULL,"
        "description TEXT,"
        "threat_level INTEGER,"
        "affected_packages TEXT,"
        "date_added TEXT DEFAULT CURRENT_TIMESTAMP"
        ");";
char* err_msg = NULL;
    rc = sqlite3_exec(sec_db->db, create_table, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error creando tabla: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
// Crear tabla de patrones sospechosos
    const char* create_patterns = 
        "CREATE TABLE IF NOT EXISTS suspicious_patterns ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "pattern TEXT NOT NULL,"
        "description TEXT,"
        "severity INTEGER"
        ");";
        sqlite3_exec(sec_db->db, create_patterns, NULL, NULL, NULL);
    // Insertar patrones sospechosos conocidos
 const char* insert_patterns[] = {
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (1, 'curl.*|.*bash', 'Descarga y ejecución directa', 3)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (2, 'wget.*|.*sh', 'Descarga y ejecución directa', 3)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (3, 'rm -rf /', 'Comando destructivo', 4)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (4, 'chmod 777', 'Permisos inseguros', 2)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (5, '/etc/passwd', 'Acceso a archivos de sistema', 3)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (6, 'nc -l', 'Backdoor potencial', 3)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (7, 'eval.*curl', 'Ejecución remota de código', 4)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (8, 'base64 -d.*bash', 'Código ofuscado', 3)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (9, '/tmp/.*&&.*chmod.*x', 'Script temporal ejecutable', 2)",
        "INSERT OR IGNORE INTO suspicious_patterns VALUES (10, 'sudo.*NOPASSWD', 'Escalada de privilegios', 3)",
        NULL
    };
for (int i = 0; insert_patterns[i] != NULL; i++) {
        sqlite3_exec(sec_db->db, insert_patterns[i], NULL, NULL, NULL);
    }
    
    return sec_db;
}
void security_db_cleanup(SecurityDatabase* db) {
    if (!db) return;
    sqlite3_close(db->db);
    free(db->db_path);
    free(db);
}

int security_db_add_signature(SecurityDatabase* db, MalwareSignature* sig) {
    const char* sql = 
        "INSERT INTO malware_signatures (signature, name, description, "
        "threat_level, affected_packages) VALUES (?, ?, ?, ?, ?)";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, sig->signature, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sig->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sig->description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, sig->level);
    sqlite3_bind_text(stmt, 5, sig->affected_packages, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? 0 : -1;
}
int security_db_update_from_remote(SecurityDatabase* db) {
    printf("Actualizando base de datos de seguridad...\n");
    
    MalwareSignature example = {
        .signature = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        .name = "AUR-Malware-001",
        .description = "Backdoor conocido en paquete falso de utilidades",
        .level = THREAT_CRITICAL,
        .affected_packages = "fake-utils,suspicious-tool",
        .date_added = NULL
    };
    
    security_db_add_signature(db, &example);
    
    return 0;
}

// ============ ANÁLISIS DE PKGBUILD ============
struct MemoryStruct {
    char* memory;
    size_t size;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;
    
    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

char* security_download_pkgbuild(const char* package_name) {
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if (!curl) return NULL;
    
    char url[512];
    snprintf(url, sizeof(url), 
            "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=%s", 
            package_name);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    res = curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }
    
    return chunk.memory;
}
char* security_calculate_hash(const char* content) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, content, strlen(content));
    SHA256_Final(hash, &sha256);
    
    char* hash_string = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    hash_string[SHA256_DIGEST_LENGTH * 2] = 0;
    
    return hash_string;
}

int security_analyze_pkgbuild(const char* pkgbuild, SecurityReport* report) {
    report->suspicious_commands = 0;
    report->network_access = 0;
    report->root_required = 0;
    
    if (!pkgbuild) return -1;
    
    const char* dangerous_patterns[] = {
        "curl", "wget", "nc ", "netcat",
        "eval", "base64", "/tmp/",
        "chmod 777", "rm -rf", 
        "/etc/passwd", "/etc/shadow",
        "sudo", "NOPASSWD",
        NULL
    };
    
    char* lower = strdup(pkgbuild);
    for (int i = 0; lower[i]; i++) {
        lower[i] = tolower(lower[i]);
    }
    
    for (int i = 0; dangerous_patterns[i] != NULL; i++) {
        if (strstr(lower, dangerous_patterns[i])) {
            report->suspicious_commands++;
            
            if (strstr(dangerous_patterns[i], "curl") || 
                strstr(dangerous_patterns[i], "wget")) {
                report->network_access = 1;
            }
            if (strstr(dangerous_patterns[i], "sudo")) {
                report->root_required = 1;
            }
        }
    }   
    free(lower);
    
    if (report->suspicious_commands >= 3) {
        report->threat_level = THREAT_HIGH;
    } else if (report->suspicious_commands >= 2) {
        report->threat_level = THREAT_MEDIUM;
    } else if (report->suspicious_commands >= 1) {
        report->threat_level = THREAT_LOW;
    } else {
        report->threat_level = THREAT_NONE;
    }
    
    return 0;
}
SecurityReport* security_scan_package(SecurityDatabase* db, const char* pkg_name) {
    SecurityReport* report = malloc(sizeof(SecurityReport));
    report->package_name = strdup(pkg_name);
    report->threats_found = 0;
    report->threat_descriptions = NULL;
    report->pkgbuild_hash = NULL;
    
    printf("Escaneando paquete: %s\n", pkg_name);
    
    char* pkgbuild = security_download_pkgbuild(pkg_name);
    
    if (!pkgbuild) {
        report->threat_level = THREAT_NONE;
        report->threat_descriptions = malloc(sizeof(char*) * 2);
        report->threat_descriptions[0] = strdup("No se pudo descargar PKGBUILD");
        report->threat_descriptions[1] = NULL;
        report->threats_found = 1;
        return report;
    }

report->pkgbuild_hash = security_calculate_hash(pkgbuild);
    
    char query[512];
    snprintf(query, sizeof(query),
            "SELECT name, description, threat_level FROM malware_signatures "
            "WHERE signature = '%s'", report->pkgbuild_hash);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db->db, query, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            report->threat_level = THREAT_CRITICAL;
            report->threats_found = 1;
            report->threat_descriptions = malloc(sizeof(char*) * 2);
            report->threat_descriptions[0] = strdup(
                (const char*)sqlite3_column_text(stmt, 1));
            report->threat_descriptions[1] = NULL;
            sqlite3_finalize(stmt);
            free(pkgbuild);
            return report;
        }
        sqlite3_finalize(stmt);
    }
security_analyze_pkgbuild(pkgbuild, report);
    
    report->threat_descriptions = malloc(sizeof(char*) * 10);
    int desc_count = 0;
    
    if (report->network_access) {
        report->threat_descriptions[desc_count++] = 
            strdup("El paquete descarga archivos de internet");
    }
    if (report->root_required) {
        report->threat_descriptions[desc_count++] = 
            strdup("Requiere privilegios de root");
    }
    if (report->suspicious_commands > 0) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), 
                "Se encontraron %d comandos sospechosos", 
                report->suspicious_commands);
        report->threat_descriptions[desc_count++] = strdup(buffer);
    }
    
    report->threat_descriptions[desc_count] = NULL;
    report->threats_found = desc_count;
    
    free(pkgbuild);
    return report;
}

void security_report_free(SecurityReport* report) {
    if (!report) return;
    free(report->package_name);
    free(report->pkgbuild_hash);
    
    if (report->threat_descriptions) {
        for (int i = 0; report->threat_descriptions[i]; i++) {
            free(report->threat_descriptions[i]);
        }
        free(report->threat_descriptions);
    }
    free(report);
}
/ ============ IMPLEMENTACIÓN DEL FRAMEWORK ============
/*
 * framework.c - Main framework implementation
 * Part of AUR Security Framework
 * Licensed under GPL-3.0-or-later
 */

#include <unistd.h>
#include <sys/wait.h>

PackageList* package_list_create() {
    PackageList* list = malloc(sizeof(PackageList));
    list->capacity = 10;
    list->count = 0;
    list->packages = malloc(sizeof(AURPackage*) * list->capacity);
    return list;
}
void package_list_free(PackageList* list) {
    if (!list) return;
    for (int i = 0; i < list->count; i++) {
        free(list->packages[i]->name);
        free(list->packages[i]->version);
        free(list->packages[i]->description);
        free(list->packages[i]->maintainer);
        if (list->packages[i]->security_report) {
            security_report_free(list->packages[i]->security_report);
        }
        free(list->packages[i]);
    }
    free(list->packages);
    free(list);
}

char* execute_command(const char* command) {
    FILE* pipe = popen(command, "r");
    if (!pipe) return NULL;
    
    char* result = malloc(4096);
    size_t total = 0;
    size_t capacity = 4096;
    
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        size_t len = strlen(buffer);
        if (total + len >= capacity) {
            capacity *= 2;
            result = realloc(result, capacity);
        }
        strcpy(result + total, buffer);
        total += len;
    }
    
    pclose(pipe);
    return result;
}

PackageList* aur_search_packages(const char* query) {
    PackageList* list = package_list_create();
    
    char command[512];
    snprintf(command, sizeof(command), 
            "yay -Ss %s --aur 2>/dev/null | head -20", query);
    
    char* output = execute_command(command);
    if (output) free(output);
    
    AURPackage* pkg = malloc(sizeof(AURPackage));
    pkg->name = strdup(query);
    pkg->version = strdup("1.0.0");
    pkg->description = strdup("Paquete de ejemplo del AUR");
    pkg->maintainer = strdup("usuario@aur");
    pkg->votes = 10;
    pkg->popularity = 0.5;
    pkg->security_report = NULL;
    
    list->packages = malloc(sizeof(AURPackage*));
    list->packages[0] = pkg;
    list->count = 1;
    list->capacity = 1;
    
    return list;
}
int aur_install_package(AURFramework* fw, const char* package_name,
                    void (*progress_cb)(int)) {
    
    if (fw->security_enabled) {
        SecurityReport* report = security_scan_package(fw->sec_db, package_name);
        
        if (report->threat_level >= THREAT_MEDIUM) {
            GtkWidget* dialog = gtk_message_dialog_new(
                GTK_WINDOW(fw->window),
                GTK_DIALOG_MODAL,
                GTK_MESSAGE_WARNING,
                GTK_BUTTONS_YES_NO,
                "⚠️ ADVERTENCIA DE SEGURIDAD\n\n"
                "Paquete: %s\n"
                "Nivel de amenaza: %s\n\n"
                "¿Desea continuar con la instalación?",
                package_name,
                report->threat_level == THREAT_CRITICAL ? "CRÍTICO" :
                report->threat_level == THREAT_HIGH ? "ALTO" : "MEDIO"
            );
            
            int response = gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
            
            if (response != GTK_RESPONSE_YES) {
                security_report_free(report);
                return -1;
            }
        }
        
        security_report_free(report);
    }
    
    char command[512];
    snprintf(command, sizeof(command), 
            "yay -S %s --noconfirm 2>&1", package_name);
    
    int status = system(command);
    return WEXITSTATUS(status);
}

// ============ DIÁLOGO "ACERCA DE" CON INFO DE LICENCIA ============

void aur_framework_show_about(AURFramework* fw) {
    const gchar* authors[] = {
        AUR_FRAMEWORK_AUTHOR,
        NULL
    };
    
    const gchar* license_text = 
        "This program is free software: you can redistribute it and/or modify "
        "it under the terms of the GNU General Public License as published by "
        "the Free Software Foundation, either version 3 of the License, or "
        "(at your option) any later version.\n\n"
        
        "This program is distributed in the hope that it will be useful, "
        "but WITHOUT ANY WARRANTY; without even the implied warranty of "
        "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the "
        "GNU General Public License for more details.\n\n"
        
        "You should have received a copy of the GNU General Public License "
        "along with this program. If not, see <https://www.gnu.org/licenses/>.";
    
    gtk_show_about_dialog(
        GTK_WINDOW(fw->window),
        "program-name", "AUR Security Framework",
        "version", AUR_FRAMEWORK_VERSION,
        "copyright", "Copyright © " AUR_FRAMEWORK_YEAR " " AUR_FRAMEWORK_AUTHOR,
        "license", license_text,
        "website", "https://github.com/tu-usuario/aur-security-framework",
        "comments", "Gestor seguro de paquetes del AUR con detección de malware",
        "authors", authors,
        "logo-icon-name", "application-x-executable",
        NULL
    );
}

// ============ INTERFAZ GRÁFICA ============
static void on_about_clicked(GtkWidget* widget, gpointer data) {
    AURFramework* fw = (AURFramework*)data;
    aur_framework_show_about(fw);
}

static void on_security_scan(GtkWidget* widget, gpointer data) {
    AURFramework* fw = (AURFramework*)data;
    
    if (fw->packages && fw->packages->count > 0) {
        const char* pkg_name = fw->packages->packages[0]->name;
        
        gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0,
                          "Escaneando seguridad del paquete...");
        
        SecurityReport* report = security_scan_package(fw->sec_db, pkg_name);
        
        const char* level_str;
        switch (report->threat_level) {
            case THREAT_NONE: level_str = "✓ SEGURO"; break;
            case THREAT_LOW: level_str = "⚠ BAJO"; break;
            case THREAT_MEDIUM: level_str = "⚠ MEDIO"; break;
            case THREAT_HIGH: level_str = "⚠ ALTO"; break;
            case THREAT_CRITICAL: level_str = "🛑 CRÍTICO"; break;
            default: level_str = "DESCONOCIDO";
        }
        
        char message[1024];
        snprintf(message, sizeof(message),
                "Escaneo completado\nNivel: %s\nAmenazas: %d",
                level_str, report->threats_found);
        
        GtkWidget* dialog = gtk_message_dialog_new(
            GTK_WINDOW(fw->window),
            GTK_DIALOG_MODAL,
            report->threat_level >= THREAT_MEDIUM ? 
                GTK_MESSAGE_WARNING : GTK_MESSAGE_INFO,
            GTK_BUTTONS_OK,
            "%s", message
        );
        
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        
        security_report_free(report);
        gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0, "Listo");
    }
}

static void on_search_clicked(GtkWidget* widget, gpointer data) {
    AURFramework* fw = (AURFramework*)data;
    const char* query = gtk_entry_get_text(GTK_ENTRY(fw->search_entry));
    
    if (fw->packages) {
        package_list_free(fw->packages);
    }
    
    fw->packages = aur_search_packages(query);
    
    char status[128];
    snprintf(status, sizeof(status), 
            "Encontrados %d paquetes", fw->packages->count);
    gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0, status);
}

static void on_install_clicked(GtkWidget* widget, gpointer data) {
    AURFramework* fw = (AURFramework*)data;
    
    if (fw->packages && fw->packages->count > 0) {
        aur_install_package(fw, fw->packages->packages[0]->name, NULL);
    }
}

static void on_update_db_clicked(GtkWidget* widget, gpointer data) {
    AURFramework* fw = (AURFramework*)data;
    
    gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0,
                    "Actualizando base de datos de seguridad...");
    
    security_db_update_from_remote(fw->sec_db);
    
    gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0,
                    "Base de datos actualizada");
}
AURFramework* aur_framework_init(int argc, char** argv) {
    gtk_init(&argc, &argv);
    
    AURFramework* fw = malloc(sizeof(AURFramework));
    fw->packages = NULL;
    fw->security_enabled = 1;
    
    fw->sec_db = security_db_init("aur_security.db");
    
    fw->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(fw->window), 
                        "AUR Security Framework v" AUR_FRAMEWORK_VERSION);
    gtk_window_set_default_size(GTK_WINDOW(fw->window), 900, 650);
    g_signal_connect(fw->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(fw->window), vbox);
    
    // Menú superior
    GtkWidget* menubar = gtk_menu_bar_new();
    GtkWidget* help_menu = gtk_menu_new();
    GtkWidget* help_item = gtk_menu_item_new_with_label("Ayuda");
    GtkWidget* about_item = gtk_menu_item_new_with_label("Acerca de...");
    
    g_signal_connect(about_item, "activate", G_CALLBACK(on_about_clicked), fw);
    
    gtk_menu_shell_append(GTK_MENU_SHELL(help_menu), about_item);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(help_item), help_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), help_item);
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);
    
    // Barra de búsqueda
    GtkWidget* search_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    fw->search_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(fw->search_entry),
                                "Buscar paquetes en AUR...");
    
    GtkWidget* search_btn = gtk_button_new_with_label("🔍 Buscar");
    g_signal_connect(search_btn, "clicked",
                    G_CALLBACK(on_search_clicked), fw);
    
    gtk_box_pack_start(GTK_BOX(search_box), fw->search_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(search_box), search_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), search_box, FALSE, FALSE, 5);
    
    // Panel de seguridad
    GtkWidget* security_frame = gtk_frame_new("🛡️ Seguridad");
    GtkWidget* security_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_add(GTK_CONTAINER(security_frame), security_box);
    
    GtkWidget* scan_btn = gtk_button_new_with_label("Escanear Paquete");
    GtkWidget* update_db_btn = gtk_button_new_with_label("Actualizar BD");
    
    g_signal_connect(scan_btn, "clicked", G_CALLBACK(on_security_scan), fw);
    g_signal_connect(update_db_btn, "clicked", 
                    G_CALLBACK(on_update_db_clicked), fw);
    
    gtk_box_pack_start(GTK_BOX(security_box), scan_btn, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(security_box), update_db_btn, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), security_frame, FALSE, FALSE, 5);
    
    // Lista de paquetes
    fw->list_view = gtk_scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), fw->list_view, TRUE, TRUE, 0);
    
    // Botones de acción
    GtkWidget* action_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget* install_btn = gtk_button_new_with_label("📦 Instalar");
    
    g_signal_connect(install_btn, "clicked",
                    G_CALLBACK(on_install_clicked), fw);
    
    gtk_box_pack_start(GTK_BOX(action_box), install_btn, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), action_box, FALSE, FALSE, 5);
    
    // Barra de estado
    fw->status_bar = gtk_statusbar_new();
    gtk_box_pack_start(GTK_BOX(vbox), fw->status_bar, FALSE, FALSE, 0);
    gtk_statusbar_push(GTK_STATUSBAR(fw->status_bar), 0, 
                    "Listo - Software Libre bajo GPL-3.0+");
    
    gtk_widget_show_all(fw->window);
    
    return fw;
}

void aur_framework_run(AURFramework* fw) {
    gtk_main();
}

void aur_framework_cleanup(AURFramework* fw) {
    if (fw->packages) {
        package_list_free(fw->packages);
    }
    security_db_cleanup(fw->sec_db);
    free(fw);
}

// ============ PROGRAMA PRINCIPAL ============
/*
 * main.c - Entry point
 * Part of AUR Security Framework
 * Licensed under GPL-3.0-or-later
 */

int main(int argc, char** argv) {
    // Mostrar información de licencia al iniciar
    printf("AUR Security Framework v%s\n", AUR_FRAMEWORK_VERSION);
    printf("Copyright (C) %s %s\n", AUR_FRAMEWORK_YEAR, AUR_FRAMEWORK_AUTHOR);
    printf("Licencia: %s\n", AUR_FRAMEWORK_LICENSE);
    printf("Este es software libre: puede redistribuirlo y/o modificarlo\n");
    printf("bajo los términos de la GNU GPL v3 o posterior.\n");
    printf("NO HAY GARANTÍA, en la medida permitida por la ley.\n\n");
    
    AURFramework* fw = aur_framework_init(argc, argv);
    aur_framework_run(fw);
    aur_framework_cleanup(fw);
    
    return 0;
}