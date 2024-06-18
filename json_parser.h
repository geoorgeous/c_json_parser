#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#undef NULL
#define NULL ((void*)0)

typedef int bool_ty;
#define BOOL_TRUE ((bool_ty)1)
#define BOOL_FALSE ((bool_ty)0)

typedef unsigned size_ty;

enum json_type_en {
    JSON_VALUE_TYPE_NULL = 0,
    JSON_VALUE_TYPE_BOOL_TRUE,
    JSON_VALUE_TYPE_BOOL_FALSE,
    JSON_VALUE_TYPE_OBJECT,
    JSON_VALUE_TYPE_ARRAY,
    JSON_VALUE_TYPE_STRING,
    JSON_VALUE_TYPE_NUMBER
};

struct json_value_st;

struct json_value_st* json_parse(const char* json_source, size_ty json_source_length);

void json_free(struct json_value_st** root);

enum json_type_en json_get_type(const struct json_value_st* json_value);

void json_init_null(struct json_value_st* json_value);
void json_init_bool(struct json_value_st* json_value);
void json_init_object(struct json_value_st* json_value);
void json_init_array(struct json_value_st* json_value);
void json_init_string(struct json_value_st* json_value);
void json_init_number(struct json_value_st* json_value);

bool_ty json_is_null(const struct json_value_st* json_value);
bool_ty json_is_bool(const struct json_value_st* json_value);
bool_ty json_is_object(const struct json_value_st* json_value);
bool_ty json_is_array(const struct json_value_st* json_value);
bool_ty json_is_string(const struct json_value_st* json_value);
bool_ty json_is_number(const struct json_value_st* json_value);

bool_ty json_bool(const struct json_value_st* json_value);
void    json_bool_set(struct json_value_st* json_value, bool_ty b);

size_ty               json_object_length(const struct json_value_st* json_value);
struct json_value_st* json_object_get(const struct json_value_st* json_value, const char* key);
struct json_value_st* json_object_add(struct json_value_st* json_value, const char* key);
void                  json_object_remove(struct json_value_st* json_value, const char* key);
void                  json_object_clear(struct json_value_st* json_value);

size_ty               json_array_length(const struct json_value_st* json_value);
struct json_value_st* json_array_get(const struct json_value_st* json_value, size_ty index);
struct json_value_st* json_array_push(struct json_value_st* json_value);
void                  json_array_remove(struct json_value_st* json_value, size_ty index);
void                  json_array_clear(struct json_value_st* json_value);

const char* json_string(const struct json_value_st* json_value);
void        json_string_set(struct json_value_st* json_value, const char* string_to_copy);

double json_number(const struct json_value_st* json_value);
void   json_number_set(struct json_value_st* json_value, double n);

#endif
