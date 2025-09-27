#include"container_lookup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <stdbool.h>

// Buffer to store data from libcurl
struct memory {
    char *response;
    size_t size;
};

static struct container_cache cache[256];
static int cache_count = 0;

// Callback for libcurl to write received data into a buffer
size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct memory *mem = (struct memory *)userdata;

    char *tmp = realloc(mem->response, mem->size + total + 1);
    if (!tmp) return 0; // out of memory
    mem->response = tmp;

    memcpy(&(mem->response[mem->size]), ptr, total);
    mem->size += total;
    mem->response[mem->size] = '\0';
    return total;
}

// Get container name and image from Docker API (using container ID)
int lookup_container_docker_info(const char *container_id, char *out_name, size_t name_sz, char *out_image, size_t image_sz) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct memory mem = {0};
    char url[256];
    snprintf(url, sizeof(url), "http://localhost/containers/%s/json", container_id);

    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(mem.response);
        return -1;
    }

    // Parse JSON response
    cJSON *root = cJSON_Parse(mem.response);
    free(mem.response);
    if (!root) return -1;

    // Name
    cJSON *name_json = cJSON_GetObjectItem(root, "Name");
    if (cJSON_IsString(name_json) && name_json->valuestring) {
        strncpy(out_name, name_json->valuestring, name_sz);
        out_name[name_sz - 1] = '\0';
        if (out_name[0] == '/') memmove(out_name, out_name + 1, strlen(out_name));
    } else {
        out_name[0] = '\0';
    }

    // Image
    cJSON *config = cJSON_GetObjectItem(root, "Config");
    cJSON *image_json = cJSON_GetObjectItem(config, "Image");
    if (cJSON_IsString(image_json) && image_json->valuestring) {
        strncpy(out_image, image_json->valuestring, image_sz);
        out_image[image_sz - 1] = '\0';
    } else {
        out_image[0] = '\0';
    }

    cJSON_Delete(root);
    return 0;
}


// Remove prefix docker://, containerd://...
const char *strip_cid_prefix(const char *cid_full) {
    if (!cid_full) return NULL;
    const char *p = strstr(cid_full, "://");
    return p ? p + 3 : cid_full;
}

// Get container name and image from k8s API (using pod UID + container ID)
int lookup_container_k8s_info(const char *target_uid, const char *target_cid, char *out_name, size_t name_len, char *out_image, size_t image_len) {
    CURL *curl;
    CURLcode res;
    struct memory chunk = {0};

    const char *url        = "https://192.168.49.2:8443/api/v1/pods";
    const char *ca_cert    = "/home/minhnn/.minikube/ca.crt";
    const char *client_cert= "/home/minhnn/.minikube/profiles/minikube/client.crt";
    const char *client_key = "/home/minhnn/.minikube/profiles/minikube/client.key";

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
    curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
    curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    int found = 0;
    cJSON *root = cJSON_Parse(chunk.response);
    if (root) {
        cJSON *items = cJSON_GetObjectItem(root, "items");
        if (cJSON_IsArray(items)) {
            cJSON *pod = NULL;
            cJSON_ArrayForEach(pod, items) {
                cJSON *metadata = cJSON_GetObjectItem(pod, "metadata");
                const char *uid = cJSON_GetObjectItem(metadata, "uid")->valuestring;

                if (uid && strcmp(uid, target_uid) == 0) {
                    cJSON *status = cJSON_GetObjectItem(pod, "status");
                    cJSON *containerStatuses = cJSON_GetObjectItem(status, "containerStatuses");
                    if (cJSON_IsArray(containerStatuses)) {
                        cJSON *cs = NULL;
                        cJSON_ArrayForEach(cs, containerStatuses) {
                            const char *cid_full = cJSON_GetObjectItem(cs, "containerID")->valuestring;
                            const char *cid = strip_cid_prefix(cid_full);

                            if (cid && strcmp(cid, target_cid) == 0) {
                                const char *cname  = cJSON_GetObjectItem(cs, "name")->valuestring;
                                const char *cimage = cJSON_GetObjectItem(cs, "image")->valuestring;

                                if (cname)  strncpy(out_name, cname, name_len - 1);
                                if (cimage) strncpy(out_image, cimage, image_len - 1);

                                out_name[name_len - 1]   = '\0';
                                out_image[image_len - 1] = '\0';

                                found = 1;
                                break;
                            }
                        }
                    }
                }
                if (found) break;
            }
        }
        cJSON_Delete(root);
    }

    free(chunk.response);
    curl_easy_cleanup(curl);
    return found ? 0 : -1;
}

int lookup_container_id_pod_uid(pid_t pid, char *container_id, size_t cid_size, char *pod_uid, size_t pod_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    char line[512];
    container_id[0] = '\0';
    if (pod_uid) pod_uid[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        // ---- Parse pod UID ----
        if (pod_uid) {
            char *pod = NULL, *tmp = line;
            // find last "pod" in line (to avoid matching "kubepods")
            while ((tmp = strstr(tmp, "pod")) != NULL) {
                pod = tmp;
                tmp += 3;
            }

            if (pod) {
                char *end = strstr(pod, ".slice");
                if (end && end > pod + 3) {
                    size_t len = end - (pod + 3); // skip "pod"
                    if (len >= pod_size) len = pod_size - 1;

                    for (size_t i = 0; i < len; i++) {
                        char c = pod[3 + i];
                        pod_uid[i] = (c == '_') ? '-' : c; // replace '_' with '-'
                    }
                    pod_uid[len] = '\0';
                }
            }
        }

        // ---- Parse container ID ----
        char *p = line;
        while ((p = strstr(p, "docker-")) != NULL) {
            char *end = strstr(p, ".scope");
            if (end) {
                size_t len = end - (p + 7); // skip "docker-"
                if (len >= cid_size) len = cid_size - 1;
                strncpy(container_id, p + 7, len);
                container_id[len] = '\0';
            }
            p += 7;
        }
    }

    fclose(f);
    return container_id[0] ? 0 : -1;
}

const struct container_cache* get_container_info(pid_t pid, unsigned long long cgroup_id) {
    // Check cache first
    for (int i = 0; i < cache_count; i++) {
        if (cache[i].cgroup_id == cgroup_id) {
            return &cache[i];
        }
    }

    bool is_docker = false;
    char container_id[128] = {0};
    char pod_uid[128] = {0};

    if (lookup_container_id_pod_uid(pid, container_id, sizeof(container_id),
                                    pod_uid, sizeof(pod_uid)) != 0) {
        return NULL; 
    }

    is_docker = (pod_uid[0] == '\0');

    if (cache_count >= 256) return NULL; 

    struct container_cache *c = &cache[cache_count++];
    c->cgroup_id = cgroup_id;
    strncpy(c->id, container_id, sizeof(c->id));
    c->id[sizeof(c->id)-1] = '\0';

    if (is_docker) {
        if (lookup_container_docker_info(container_id, c->name, sizeof(c->name),
                                        c->image, sizeof(c->image)) < 0) {
            c->name[0] = '\0';
            c->image[0] = '\0';
        }
    } else {
        if (lookup_container_k8s_info(pod_uid, container_id, c->name, sizeof(c->name),
                                      c->image, sizeof(c->image)) < 0) {
            c->name[0] = '\0';
            c->image[0] = '\0';
        }
    }

    return c; 
}
