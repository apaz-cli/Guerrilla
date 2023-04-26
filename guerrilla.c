#define _GNU_SOURCE // for vasprintf
#include "cJSON.h"
#include <curl/curl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  char *response;
  char *sid_token;
  cJSON *json;
} GuerrillaResponse;

static inline void guerrilla_response_free(GuerrillaResponse response) {
  free(response.response);
  free(response.sid_token);
  cJSON_Delete(response.json);
}

typedef struct {
  char *email_addr;
  uint64_t email_timestamp;
  char *alias;
  char *sid_token;
} GuerrillaAddress;

static inline void guerrilla_address_free(GuerrillaAddress address) {
  free(address.email_addr);
  free(address.alias);
  free(address.sid_token);
}

static inline size_t libcurl_write_callback(char *ptr, size_t size,
                                            size_t nmemb, void *userdata) {
  size = size * nmemb;
  char **response = (char **)userdata;
  size_t current_len = *response ? strlen(*response) : 0;
  *response = realloc(*response, current_len + size + 1);
  memcpy(*response + current_len, ptr, size);
  (*response)[current_len + size] = '\0';
  return size;
}

#define RANDBUFSZ 64
static int randfd = 0;
static int randbuf[RANDBUFSZ];
static size_t randbufremaining = 0;

static inline int randint(void) {
  if (!randfd) {
    randfd = open("/dev/random", O_RDONLY);
    if (randfd < 0)
      fprintf(stderr, "Cannot open /dev/random.\n"), perror("open"), exit(1);
  }

  if (!randbufremaining) {
    int r = read(randfd, &randbuf, sizeof(randbuf));
    if (r < 0)
      fprintf(stderr, "Cannot read from /dev/random.\n"), perror("read"),
          exit(1);
    randbufremaining = RANDBUFSZ;
  }

  int ret = randbuf[--randbufremaining];
  int mask = ~(1 << ((sizeof(int) * CHAR_BIT) - 1));
  ret &= mask;
  return ret;
}
static inline void closeint(void) { close(randfd); }

static inline GuerrillaResponse guerrilla_request(char *sid_token, char *fmt,
                                                  ...) {

  char *fields = NULL;
  va_list args;
  va_start(args, fmt);
  vasprintf(&fields, fmt, args);
  va_end(args);
  if (!fields)
    return (GuerrillaResponse){NULL, NULL, NULL};

  CURL *curl;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if (!curl) {
    free(fields);
    return (GuerrillaResponse){NULL, NULL, NULL};
  }

  char *response = NULL;
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_URL, "https://api.guerrillamail.com/ajax.php");
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, libcurl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

  // Set session id token
  char *cookie = NULL;
  if (sid_token) {
    asprintf(&cookie, "Cookie: PHPSESSID=%s", sid_token);
    if (!cookie) {
      free(fields);
      free(response);
      curl_easy_cleanup(curl);
      return (GuerrillaResponse){NULL, NULL, NULL};
    }

    curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
  }

  // Make the request
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    free(fields);
    free(response);
    curl_easy_cleanup(curl);
    return (GuerrillaResponse){NULL, NULL, NULL};
  }

  free(fields);
  free(cookie);

  // Get the response code
  long response_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  if (response_code != 200) {
    printf("Failed with response code %ld\n", response_code);
    free(response);
    curl_easy_cleanup(curl);
    return (GuerrillaResponse){NULL, NULL, NULL};
  }

  curl_easy_cleanup(curl);

  cJSON *json = cJSON_Parse(response);
  if (!json) {
    printf(response ? "Failed to parse JSON\n" : "Failed to get response\n");
    free(response);
    return (GuerrillaResponse){NULL, NULL, NULL};
  }

  // Get the email sid token
  cJSON *sid_token_json = cJSON_GetObjectItem(json, "sid_token");
  if (!sid_token_json) {
    printf("Failed to get sid token\n");
    free(response);
    cJSON_Delete(json);
    return (GuerrillaResponse){NULL, NULL, NULL};
  }

  return (GuerrillaResponse){response, strdup(sid_token_json->valuestring),
                             json};
}

static inline GuerrillaAddress guerrilla_get_address(void) {

  GuerrillaResponse resp = guerrilla_request(NULL, "f=get_email_address");
  if (!resp.response || !resp.json)
    return (GuerrillaAddress){NULL, 0, NULL, NULL};

  // Get the email address
  cJSON *email_address_json = cJSON_GetObjectItem(resp.json, "email_addr");
  if (!email_address_json) {
    guerrilla_response_free(resp);
    return (GuerrillaAddress){NULL, 0, NULL, NULL};
  }
  char *email_address = strdup(email_address_json->valuestring);

  // Get the email timestamp
  cJSON *email_timestamp_json =
      cJSON_GetObjectItem(resp.json, "email_timestamp");
  if (!email_timestamp_json) {
    guerrilla_response_free(resp);
    return (GuerrillaAddress){NULL, 0, NULL, NULL};
  }
  uint64_t email_timestamp = email_timestamp_json->valuedouble;

  // Get the email alias
  cJSON *alias_json = cJSON_GetObjectItem(resp.json, "alias");
  if (!alias_json) {
    guerrilla_response_free(resp);
    return (GuerrillaAddress){NULL, 0, NULL, NULL};
  }
  char *alias = strdup(alias_json->valuestring);

  // Get the email sid token
  char *sid_token = strdup(resp.sid_token);

  guerrilla_response_free(resp);
  return (GuerrillaAddress){email_address, email_timestamp, alias, sid_token};
}

static inline cJSON *guerilla_check_email(GuerrillaAddress *gaddress) {

  GuerrillaResponse resp =
      guerrilla_request(gaddress->sid_token, "f=check_email&seq=0&sid_token=%s",
                        gaddress->sid_token);
  if (!resp.response || !resp.json || !resp.sid_token)
    return NULL;

  // Check for error string
  cJSON *error_json = cJSON_GetObjectItem(resp.json, "error");
  if (error_json) {
    printf("Error: %s\n", error_json->valuestring);
    guerrilla_response_free(resp);
    return 0;
  }

  // Get the list
  cJSON *list_json = cJSON_GetObjectItem(resp.json, "list");
  if (!list_json) {
    guerrilla_response_free(resp);
    return NULL;
  }

  // Copy and return the list
  cJSON *list_copy = cJSON_Duplicate(list_json, 1);
  guerrilla_response_free(resp);
  return list_copy;
}

static inline void stream_email(GuerrillaAddress *gaddress) {

  int expecting = 1; // Disregard the intro email
  while (1) {
    cJSON *email_list = guerilla_check_email(gaddress);
    size_t sleeptime = 5;
    int recvd = email_list ? cJSON_GetArraySize(email_list) : 0;
    if (!email_list) {
      printf("Error checking email.\n");
      break;
    } else if (recvd > expecting) {
      // Pretty print the newest email.
      cJSON *email = cJSON_GetArrayItem(email_list, expecting);
      cJSON *subject = cJSON_GetObjectItem(email, "Subject");
      cJSON *body = cJSON_GetObjectItem(email, "Body");
      printf("Subject: %s\n"
             "Body: %s\n",
             subject->valuestring, body->valuestring);
      break;
    } else {
      sleep(sleeptime);
      if (sleeptime < 10)
        sleeptime++;
    }
    expecting = 0;
    free(email_list);
  }
}

static inline char *rand_sep(void) {
  int sep = randint() % 4;
  if (sep == 0)
    return "";
  else if (sep == 1)
    return ".";
  else if (sep == 2)
    return "_";
  else if (sep == 3)
    return "-";
  return "";
}

static inline char *generate_email_address(void) {
  static char *first_names[] = {
#include "firstnames"
  };
  static size_t num_first_names = sizeof(first_names) / sizeof(char *);
  static char *last_names[] = {
#include "lastnames"
  };
  static size_t num_last_names = sizeof(last_names) / sizeof(char *);

  int append_number = randint() % 2;

  // Generate a random first name
  char *first_name = first_names[randint() % num_first_names];
  char *last_name = last_names[randint() % num_last_names];
  int number = append_number ? randint() % 100 : 0;

  int flsep = randint() % 4;
  char *sep1 = rand_sep();
  char *sep2 = append_number ? rand_sep() : "";
  char numstr[4] = {'\0', '\0', '\0', '\0'};
  if (append_number)
    sprintf(numstr, "%i", number);

  char *email_address = NULL;
  asprintf(&email_address, "%s%s%s%s%s", first_name, sep1, last_name, sep2, numstr);
  return email_address;
}

static inline char *generate_password(size_t passlen) {
  static char passchars[] = {
      'a', 'b', 'c', 'd', 'e', 'f', 'g',  'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't',  'u', 'v', 'w', 'x', 'y', 'z',
      'A', 'B', 'C', 'D', 'E', 'F', 'G',  'H', 'I', 'J', 'K', 'L', 'M',
      'N', 'O', 'P', 'Q', 'R', 'S', 'T',  'U', 'V', 'W', 'X', 'Y', 'Z',
      '1', '2', '3', '4', '5', '6', '7',  '8', '9', '"', '!', '@', '\'',
      '#', '$', '%', '^', '&', '*', '(',  ')', '-', '_', '+', '=', ':',
      ';', '<', '>', ',', '.', '/', '\\', '{', '}', '`', '~', '|'};
  static size_t num_passchars = sizeof(passchars) / sizeof(char);
  char *passwd = malloc(passlen + 1);
  for (size_t i = 0; i < passlen; i++)
    passwd[i] = passchars[randint() % num_passchars];
  passwd[passlen] = '\0';
  return passwd;
}

static inline char *generate_rand_length_password(void) {
  return generate_password(randint() % 12 + 16);
}

static inline void protonRegister(GuerrillaAddress *gaddress) {}

int main(void) {
  GuerrillaAddress addr = guerrilla_get_address();

  char *uname = generate_email_address();
  char *pass = generate_rand_length_password();
  printf("Guermail: %s\n"
         "Username: %s\n"
         "Password: %s\n",
         addr.email_addr, uname, pass);
  fflush(stdout);

  // stream_email(&addr);

  free(uname);
  free(pass);
  guerrilla_address_free(addr);
}
