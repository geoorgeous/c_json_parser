#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_parser.h"

struct json_parser_st {
    size_ty json_source_length;
    const char* json_source;
    const char* last_char;
    int parse_error;
};

struct json_object_table_st {
    size_ty num_elements;
    size_ty num_hash_table_buckets;
    struct hash_table_bucket_st* hash_table_buckets;
};

struct json_array_st {
    size_ty capacity;
    size_ty length;
    struct json_value_st* data;
};

struct json_value_st {
    enum json_type_en type;
    union {
        struct json_object_table_st as_object_table;
        struct json_array_st as_array;
        char* as_string;
        double as_number;
    } value;
};

struct hash_table_bucket_element_st {
    char* key;
    struct json_value_st value;
    struct hash_table_bucket_element_st* next;
};

struct hash_table_bucket_st {
    struct hash_table_bucket_element_st* first;
    struct hash_table_bucket_element_st* last;
};

bool_ty json_parse_value(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_null(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_bool(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_object(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_array(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_string(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_value_number(struct json_parser_st* parser, struct json_value_st* json_value);
bool_ty json_parse_string(struct json_parser_st* parser, char** string);

#define HASH_TABLE_LOAD_THRESHOLD 0.75f
size_ty hash_string(const char* str);
void hash_table_bucket_append(struct hash_table_bucket_st* hash_table_bucket, struct hash_table_bucket_element_st* element);
struct hash_table_bucket_element_st* hash_table_bucket_find(const struct hash_table_bucket_st* hash_table_bucket, const char* key);
struct hash_table_bucket_st* json_object_table_find_bucket(const struct json_value_st* json_value, const char* key);
bool_ty json_object_table_resize(struct json_value_st* json_value, size_ty new_num_buckets);

void json_reset_value(struct json_value_st* json_value) {
    switch (json_value->type) {
        case JSON_VALUE_TYPE_OBJECT:
            json_object_clear(json_value);
            break;
        case JSON_VALUE_TYPE_ARRAY:
            json_array_clear(json_value);
            break;
        case JSON_VALUE_TYPE_STRING:
            free(json_value->value.as_string);
            json_value->value.as_string = NULL;
            break;
        case JSON_VALUE_TYPE_NUMBER:
            json_value->value.as_number = 0;
            break;
        default:
            break;
    }
}

void json_parser_next_token(struct json_parser_st* parser) {
    int n = 0;
    sscanf(++parser->last_char, " %n", &n);
    parser->last_char += n;
}

struct json_value_st* json_parse(const char* json_source, size_ty json_source_length) {
    struct json_parser_st parser;
    parser.json_source_length = json_source_length;
    parser.json_source = json_source;
    parser.last_char = parser.json_source;
    
    int n = 0;
    sscanf(parser.last_char, " %n", &n);
    parser.last_char += n;

    struct json_value_st* root = malloc(sizeof(struct json_value_st));
    if (root == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for JSON root.\n");
        return NULL;
    }
    if (json_parse_value_object(&parser, root) || json_parse_value_array(&parser, root))
        return root;
    free(root);
    return NULL;
}

void json_free(struct json_value_st** root) {
    json_reset_value(*root);
    free(*root);
    *root = NULL;
}

enum json_type_en json_get_type(const struct json_value_st* json_value) {
    return json_value->type;
}

bool_ty json_is_null(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_NULL;
}

bool_ty json_is_bool(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_BOOL_TRUE || json_value->type == JSON_VALUE_TYPE_BOOL_FALSE;
}

bool_ty json_is_object(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_OBJECT;
}

bool_ty json_is_array(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_ARRAY;
}

bool_ty json_is_string(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_STRING;
}

bool_ty json_is_number(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_NUMBER;
}

void json_init_null(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_NULL;
}

void json_init_bool(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_BOOL_FALSE;
}

void json_init_object(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_OBJECT;
    json_value->value.as_object_table.num_elements = 0;
    json_value->value.as_object_table.num_hash_table_buckets = 0;
    json_value->value.as_object_table.hash_table_buckets = NULL;
}

void json_init_array(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_ARRAY;
    json_value->value.as_array.capacity = 0;
    json_value->value.as_array.length = 0;
    json_value->value.as_array.data = NULL;
}

void json_init_string(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_STRING;
    json_value->value.as_string = NULL;
}

void json_init_number(struct json_value_st* json_value) {
    json_value->type = JSON_VALUE_TYPE_NUMBER;
    json_value->value.as_number = 0;
}

bool_ty json_bool(const struct json_value_st* json_value) {
    return json_value->type == JSON_VALUE_TYPE_BOOL_TRUE ? BOOL_TRUE : BOOL_FALSE;
}

void json_bool_set(struct json_value_st* json_value, bool_ty bool_value) {
    if (json_is_bool(json_value))
        json_value->type = bool_value ? JSON_VALUE_TYPE_BOOL_TRUE : JSON_VALUE_TYPE_BOOL_FALSE;
}

size_ty json_object_length(const struct json_value_st* json_value) {
    if (json_is_object(json_value))
        return json_value->value.as_object_table.num_elements;
    return 0;
}

struct json_value_st* json_object_get(const struct json_value_st* json_value, const char* key) {
    if (!json_is_object(json_value))
        return NULL;
    struct hash_table_bucket_element_st* bucket_element = hash_table_bucket_find(json_object_table_find_bucket(json_value, key), key);
    if (bucket_element == NULL)
        return NULL;
    return &bucket_element->value;
}

struct json_value_st* json_object_add(struct json_value_st* json_value, const char* key) {
    if (!json_is_object(json_value))
        return NULL;

    struct hash_table_bucket_st* bucket = NULL;
    struct hash_table_bucket_element_st* element = NULL;

    if (json_value->value.as_object_table.num_hash_table_buckets == 0) {
        if (!json_object_table_resize(json_value, 1))
            return NULL;
        bucket = json_value->value.as_object_table.hash_table_buckets;
    } else {
        bucket = json_object_table_find_bucket(json_value, key);
        element = hash_table_bucket_find(bucket, key);
        if (element != NULL)
            return &element->value;

        if ((float)(json_value->value.as_object_table.num_elements + 1) / json_value->value.as_object_table.num_hash_table_buckets > HASH_TABLE_LOAD_THRESHOLD) {
            json_object_table_resize(json_value, json_value->value.as_object_table.num_hash_table_buckets * 2);
            bucket = json_object_table_find_bucket(json_value, key);
        }
    }

    element = malloc(sizeof(struct hash_table_bucket_element_st));
    if (element == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for JSON Object hash table bucket element.\n");
        return NULL;
    }
    element->key = strdup(key);
    json_init_null(&element->value);
    element->next = NULL;
    ++json_value->value.as_object_table.num_elements;

    hash_table_bucket_append(bucket, element);

    return &element->value;
}

void json_object_remove(struct json_value_st* json_value, const char* key) {
    if (!json_is_object(json_value))
        return;
    struct hash_table_bucket_st* hash_table_bucket = json_object_table_find_bucket(json_value, key);
    if (hash_table_bucket == NULL)
        return;

    struct hash_table_bucket_element_st* prev_bucket_element = NULL;
    struct hash_table_bucket_element_st* bucket_element = hash_table_bucket->first;
    while (bucket_element != NULL) {
        if (strcmp(key, bucket_element->key) != 0) {
            prev_bucket_element = bucket_element;
            bucket_element = bucket_element->next;
        } else {
            if (hash_table_bucket->first == hash_table_bucket->last)
                hash_table_bucket->first = hash_table_bucket->last = NULL;
            else if (prev_bucket_element == NULL)
                hash_table_bucket->first = bucket_element->next;
            else
                prev_bucket_element->next = bucket_element->next;
            free(bucket_element->key);
            json_reset_value(&bucket_element->value);
            free(bucket_element);
            --json_value->value.as_object_table.num_elements;
            break;
        }
    }
    
}

void json_object_clear(struct json_value_st* json_value) {
    if (!json_is_object(json_value))
        return;
    for (size_ty i = 0; i < json_value->value.as_object_table.num_hash_table_buckets; ++i) {
        struct hash_table_bucket_element_st* element = json_value->value.as_object_table.hash_table_buckets[i].first;
        while (element != NULL) {
            struct hash_table_bucket_element_st* next = element->next;
            json_reset_value(&element->value);
            free(element->key);
            free(element);
            element = next;
        }
    }
    free(json_value->value.as_object_table.hash_table_buckets);
    json_value->value.as_object_table.num_elements = 0;
    json_value->value.as_object_table.num_hash_table_buckets = 0;
    json_value->value.as_object_table.hash_table_buckets = NULL;
}

size_ty json_array_length(const struct json_value_st* json_value) {
    if (json_is_array(json_value))
        return json_value->value.as_array.length;
    return 0;
}

struct json_value_st* json_array_get(const struct json_value_st* json_value, size_ty index) {
    if (!json_is_array(json_value) || json_value->value.as_array.length <= index)
        return NULL;
    return json_value->value.as_array.data + index;
}

bool_ty json_array_set_capacity(struct json_value_st* json_value, size_ty new_capacity) {
    if (!json_is_array(json_value))
        return BOOL_FALSE;
    if (json_value->value.as_array.capacity == new_capacity)
        return BOOL_TRUE;
    struct json_value_st* new_data = realloc(json_value->value.as_array.data, new_capacity * sizeof(struct json_value_st));
    if (new_data == NULL) {
        fprintf(stderr, "Error: Failed to reallocate memory for JSON Array.\n");
        return BOOL_FALSE;
    }
    json_value->value.as_array.capacity = new_capacity;
    json_value->value.as_array.data = new_data;
    if (json_value->value.as_array.length > json_value->value.as_array.capacity)
        json_value->value.as_array.length = json_value->value.as_array.capacity;
    return BOOL_TRUE;
}

struct json_value_st* json_array_push(struct json_value_st* json_value) {
    if (!json_is_array(json_value))
        return NULL;
    if (json_value->value.as_array.capacity == json_value->value.as_array.length && !json_array_set_capacity(json_value, (json_value->value.as_array.capacity == 0) ? 1 : (json_value->value.as_array.capacity * 2)))
        return NULL;
    json_init_null(json_value->value.as_array.data + json_value->value.as_array.length);
    return json_value->value.as_array.data + json_value->value.as_array.length++;
}

void json_array_remove(struct json_value_st* json_value, size_ty index) {
    if (!json_is_array(json_value) || json_value->value.as_array.length <= index)
        return;
    if (--json_value->value.as_array.length != 0 && index != json_value->value.as_array.length)
        memcpy((json_value->value.as_array.data + index), json_value->value.as_array.data + json_value->value.as_array.length - 1, sizeof(struct json_value_st));
    if (json_value->value.as_array.length == 0) {
        json_value->value.as_array.capacity = 0;
        free(json_value->value.as_array.data);
        json_value->value.as_array.data = NULL;
    } else if (json_value->value.as_array.length <= json_value->value.as_array.capacity / 2) {
        size_ty new_capacity = json_value->value.as_array.capacity / 2;
        json_array_set_capacity(json_value, new_capacity);
    }
}

void json_array_clear(struct json_value_st* json_value) {
    if (!json_is_array(json_value) || json_value->value.as_array.capacity == 0)
        return;
    for (size_ty i = 0; i < json_value->value.as_array.length; ++i)
        json_reset_value(json_value->value.as_array.data + i);
    json_value->value.as_array.capacity = json_value->value.as_array.length = 0;
    free(json_value->value.as_array.data);
    json_value->value.as_array.data = NULL;
}

const char* json_string(const struct json_value_st* json_value) {
    if (json_is_string(json_value))
        return json_value->value.as_string;
    return NULL;
}

void json_string_set(struct json_value_st* json_value, const char* string_to_copy) {
    if (json_is_string(json_value)) {
        if (json_value->value.as_string != NULL)
            free(json_value->value.as_string);
        json_value->value.as_string = strdup(string_to_copy);
        if (json_value->value.as_string == NULL)
            fprintf(stderr, "Error: Failed to allocate memory for JSON string.\n");
    }
}

double json_number(const struct json_value_st* json_value) {
    if (json_is_number(json_value))
        return json_value->value.as_number;
    return 0;
}

void json_number_set(struct json_value_st* json_value, double number_value) {
    if (json_is_number(json_value))
        json_value->value.as_number = number_value;
}

// Parsing

bool_ty json_parse_value(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (json_parse_value_object(parser, json_value) ||
        json_parse_value_array(parser, json_value) ||
        json_parse_value_string(parser, json_value) ||
        json_parse_value_null(parser, json_value) ||
        json_parse_value_bool(parser, json_value) ||
        json_parse_value_number(parser, json_value))
        return BOOL_TRUE;
    fprintf(stderr, "Error: Unexpected token '%c'.\n", *parser->last_char);
    return BOOL_FALSE;
}

bool_ty json_parse_value_null(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (*parser->last_char != 'n' || *++parser->last_char != 'u' || *++parser->last_char != 'l' || *++parser->last_char != 'l')
        return BOOL_FALSE;
    json_value->type = JSON_VALUE_TYPE_NULL;
    return BOOL_TRUE;
}

bool_ty json_parse_value_bool(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (*parser->last_char == 't') {
        if (*++parser->last_char == 'r' && *++parser->last_char == 'u' && *++parser->last_char == 'e')
            json_value->type = JSON_VALUE_TYPE_BOOL_TRUE;
    } else if (*parser->last_char == 'f') {
         if (*++parser->last_char == 'a' && *++parser->last_char == 'l' && *++parser->last_char == 's' && *++parser->last_char == 'e')
            json_value->type = JSON_VALUE_TYPE_BOOL_FALSE;
    } else
        json_value->type = JSON_VALUE_TYPE_NULL;
    return json_is_bool(json_value);
}

bool_ty json_parse_value_object(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (*parser->last_char != '{')
        return BOOL_FALSE;
    json_init_object(json_value);
    for (;;) {
        json_parser_next_token(parser);
        if (*parser->last_char == '}')
            return BOOL_TRUE;
        if (json_value->value.as_object_table.num_elements > 0 && *parser->last_char == ',')
            json_parser_next_token(parser);

        char* key = NULL;
        if (!json_parse_string(parser, &key)) {
            break;
        }

        json_parser_next_token(parser);
        if (*parser->last_char == ':') {
            json_parser_next_token(parser);
            struct json_value_st property_value;
            if (json_parse_value(parser, &property_value)) {
                struct json_value_st* new_object_property = json_object_add(json_value, key);
                if (new_object_property != NULL) {
                    memcpy(new_object_property, &property_value, sizeof(struct json_value_st));
                } else 
                    fprintf(stderr, "Error: Failed to add property \"%s\" to object.\n", key);
            } else {
                free(key);
                break;
            }
            free(key);
        } else {
            fprintf(stderr, "Error: Expected ':' after property name.\n");
            free(key);
            break;
        }
    }
    json_reset_value(json_value);
    json_init_null(json_value);
    return BOOL_FALSE;
}

bool_ty json_parse_value_array(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (*parser->last_char != '[')
        return BOOL_FALSE;
    json_init_array(json_value);
    for (;;) {
        json_parser_next_token(parser);
        if (*parser->last_char == ']')
            return BOOL_TRUE;
        if (json_value->value.as_array.length > 0 && *parser->last_char == ',')
            json_parser_next_token(parser);
        struct json_value_st array_value;
        if (!json_parse_value(parser, &array_value))
            break;
        struct json_value_st* new_array_item = json_array_push(json_value);
        if (new_array_item == NULL)
            fprintf(stderr, "Error: Failed to add element to array.\n");
        else 
            memcpy(new_array_item, &array_value, sizeof(struct json_value_st));
    }
    json_reset_value(json_value);
    json_init_null(json_value);
    return BOOL_FALSE;
}

bool_ty json_parse_value_string(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (!json_parse_string(parser, &json_value->value.as_string))
        return BOOL_FALSE;
    json_value->type = JSON_VALUE_TYPE_STRING;
    return BOOL_TRUE;
}

bool_ty json_parse_value_number(struct json_parser_st* parser, struct json_value_st* json_value) {
    if (*parser->last_char != '-' && (*parser->last_char < '0' || *parser->last_char > '9'))
        return BOOL_FALSE;

    char* errptr;
    double number = strtod(parser->last_char, &errptr);
    if (errptr == parser->last_char) {
        fprintf(stderr, "Error: Failed to parse JSON number.\n");
        return BOOL_FALSE;
    }

    json_init_number(json_value);
    json_value->value.as_number = number;
    parser->last_char = errptr - 1;
    return BOOL_TRUE;
}

bool_ty json_parse_string(struct json_parser_st* parser, char** string) {
    if (*parser->last_char != '"')
        return BOOL_FALSE;
    const char* string_source = parser->last_char + 1;
    for (;;) {
        parser->last_char++;
        if (*parser->last_char == '"') {
            size_t temp_string_length = parser->last_char - string_source;
            if (temp_string_length > 0) {
                *string = malloc(sizeof(char) * (temp_string_length + 1));
                if (*string == NULL) {
                    fprintf(stderr, "Error: Failed to allocate memory for parsed JSON string.\n");
                    return BOOL_FALSE;
                }
                strncpy(*string, string_source, temp_string_length);
                (*string)[temp_string_length] = '\0';
            }
            return BOOL_TRUE;
        }
        if (*parser->last_char == '\\') {
            parser->last_char++;
            switch (*parser->last_char) {
                case '"':
                case '\\':
                case '/':
                case 'b':
                case 'f':
                case 'n':
                case 'r':
                case 't':
                    break;
                case 'u':
                    for (int i = 0; i < 4; ++i) {
                        parser->last_char++;
                        if (!((*parser->last_char >= '0' && *parser->last_char <= '9') || (*parser->last_char >= 'a' && *parser->last_char <= 'f') || (*parser->last_char >= 'A' && *parser->last_char <= 'F'))) {
                            fprintf(stderr, "Error: Bad unicode escape.\n");
                            return BOOL_FALSE;
                        }
                    }
                    break;
            }
        }
        else if (parser->last_char - parser->json_source >= parser->json_source_length)
            break;
    }
    fprintf(stderr, "Error parsing JSON string: Unterminated string.\"\n");
    return BOOL_FALSE;
}

// Hash table

size_ty hash_string(const char* str) {
    size_ty h = 0;
    for (unsigned char* p = (unsigned char*)str; *p != '\0'; p++)
        h = 37 * h + *p;
    return (size_ty)h;
}

void hash_table_bucket_append(struct hash_table_bucket_st* hash_table_bucket, struct hash_table_bucket_element_st* element) {
    if (hash_table_bucket->first == NULL) {
        hash_table_bucket->first = element;
        hash_table_bucket->last = hash_table_bucket->first;
    } else {
        hash_table_bucket->last->next = element;
        hash_table_bucket->last = hash_table_bucket->last->next;
    }
    hash_table_bucket->last->next = NULL;
}

struct hash_table_bucket_element_st* hash_table_bucket_find(const struct hash_table_bucket_st* hash_table_bucket, const char* key) {
    struct hash_table_bucket_element_st* bucket_element = hash_table_bucket->first;
    while (bucket_element != NULL) {
        if (strcmp(key, bucket_element->key) == 0)
            return bucket_element;
        bucket_element = bucket_element->next;
    }
    return NULL;
}

struct hash_table_bucket_st* json_object_table_find_bucket(const struct json_value_st* json_value, const char* key) {
    return json_value->value.as_object_table.hash_table_buckets + (hash_string(key) % json_value->value.as_object_table.num_hash_table_buckets);
}

bool_ty json_object_table_resize(struct json_value_st* json_value, size_ty new_num_buckets) {
    if (json_value->value.as_object_table.num_hash_table_buckets == new_num_buckets)
        return BOOL_TRUE;

    struct hash_table_bucket_st* old_buckets = json_value->value.as_object_table.hash_table_buckets;
    const size_ty old_num_buckets = json_value->value.as_object_table.num_hash_table_buckets;

    struct hash_table_bucket_st* new_hash_table_buckets = calloc(new_num_buckets, sizeof(struct hash_table_bucket_st)); 
    if (new_hash_table_buckets == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for JSON Object hash table buckets.\n");
        return BOOL_FALSE;
    }
    json_value->value.as_object_table.num_hash_table_buckets = new_num_buckets;
    json_value->value.as_object_table.hash_table_buckets = new_hash_table_buckets;

    for (size_ty i = 0; i < old_num_buckets; ++i) {
        struct hash_table_bucket_element_st* bucket_element = old_buckets[i].first;
        while (bucket_element != NULL) {
            struct hash_table_bucket_element_st* next = bucket_element->next;
            hash_table_bucket_append(json_object_table_find_bucket(json_value, bucket_element->key), bucket_element);
            bucket_element = next;
        }
    }

    free(old_buckets);
    return BOOL_TRUE;
}