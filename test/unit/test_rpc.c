/**
 * Bitcoin Echo — RPC Interface Tests
 *
 * Tests for Session 9.3: RPC Interface
 *
 * Verifies:
 * - JSON parsing (embedded minimal parser)
 * - JSON building (response construction)
 * - RPC request/response formatting
 * - Utility functions (hex encoding, hash formatting)
 * - RPC method handlers (unit tests with mock node)
 *
 * Build once. Build right. Stop.
 */

#include "rpc.h"
#include "block.h"
#include "consensus.h"
#include "echo_types.h"
#include "mempool.h"
#include "node.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    printf("Running test: %s...", name);                                       \
    tests_run++;                                                               \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    printf(" PASS\n");                                                         \
    tests_passed++;                                                            \
  } while (0)

/*
 * ============================================================================
 * TEST: JSON Parser - Basic Types
 * ============================================================================
 */

static void test_json_parse_null(void) {
  TEST("JSON parse null");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("null", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_NULL);

  json_free(value);
  PASS();
}

static void test_json_parse_true(void) {
  TEST("JSON parse true");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("true", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_BOOL);
  assert(value->u.boolean == true);

  json_free(value);
  PASS();
}

static void test_json_parse_false(void) {
  TEST("JSON parse false");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("false", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_BOOL);
  assert(value->u.boolean == false);

  json_free(value);
  PASS();
}

static void test_json_parse_integer(void) {
  TEST("JSON parse integer");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("42", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_NUMBER);
  assert(value->u.number == 42.0);

  json_free(value);
  PASS();
}

static void test_json_parse_negative(void) {
  TEST("JSON parse negative number");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("-123", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_NUMBER);
  assert(value->u.number == -123.0);

  json_free(value);
  PASS();
}

static void test_json_parse_float(void) {
  TEST("JSON parse float");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("3.14159", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_NUMBER);
  assert(value->u.number > 3.14 && value->u.number < 3.15);

  json_free(value);
  PASS();
}

static void test_json_parse_string(void) {
  TEST("JSON parse string");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("\"hello world\"", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_STRING);
  assert(strcmp(value->u.string, "hello world") == 0);

  json_free(value);
  PASS();
}

static void test_json_parse_escaped_string(void) {
  TEST("JSON parse escaped string");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("\"line1\\nline2\"", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_STRING);
  assert(strcmp(value->u.string, "line1\nline2") == 0);

  json_free(value);
  PASS();
}

static void test_json_parse_empty_string(void) {
  TEST("JSON parse empty string");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("\"\"", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_STRING);
  assert(strlen(value->u.string) == 0);

  json_free(value);
  PASS();
}

/*
 * ============================================================================
 * TEST: JSON Parser - Arrays
 * ============================================================================
 */

static void test_json_parse_empty_array(void) {
  TEST("JSON parse empty array");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("[]", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_ARRAY);
  assert(json_array_length(value) == 0);

  json_free(value);
  PASS();
}

static void test_json_parse_array_numbers(void) {
  TEST("JSON parse array of numbers");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("[1, 2, 3]", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_ARRAY);
  assert(json_array_length(value) == 3);

  json_value_t *elem0 = json_array_get(value, 0);
  json_value_t *elem1 = json_array_get(value, 1);
  json_value_t *elem2 = json_array_get(value, 2);

  assert(elem0 != NULL && elem0->type == JSON_NUMBER && elem0->u.number == 1.0);
  assert(elem1 != NULL && elem1->type == JSON_NUMBER && elem1->u.number == 2.0);
  assert(elem2 != NULL && elem2->type == JSON_NUMBER && elem2->u.number == 3.0);

  json_free(value);
  PASS();
}

static void test_json_parse_mixed_array(void) {
  TEST("JSON parse mixed array");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("[1, \"two\", true, null]", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_ARRAY);
  assert(json_array_length(value) == 4);

  assert(json_array_get(value, 0)->type == JSON_NUMBER);
  assert(json_array_get(value, 1)->type == JSON_STRING);
  assert(json_array_get(value, 2)->type == JSON_BOOL);
  assert(json_array_get(value, 3)->type == JSON_NULL);

  json_free(value);
  PASS();
}

/*
 * ============================================================================
 * TEST: JSON Parser - Objects
 * ============================================================================
 */

static void test_json_parse_empty_object(void) {
  TEST("JSON parse empty object");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("{}", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_OBJECT);

  json_free(value);
  PASS();
}

static void test_json_parse_simple_object(void) {
  TEST("JSON parse simple object");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("{\"name\": \"echo\", \"version\": 1}", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_OBJECT);

  json_value_t *name = json_object_get(value, "name");
  json_value_t *version = json_object_get(value, "version");

  assert(name != NULL && name->type == JSON_STRING);
  assert(strcmp(name->u.string, "echo") == 0);
  assert(version != NULL && version->type == JSON_NUMBER);
  assert(version->u.number == 1.0);

  json_free(value);
  PASS();
}

static void test_json_parse_nested_object(void) {
  TEST("JSON parse nested object");

  json_value_t *value = NULL;
  echo_result_t res =
      json_parse("{\"outer\": {\"inner\": 42}}", &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_OBJECT);

  json_value_t *outer = json_object_get(value, "outer");
  assert(outer != NULL && outer->type == JSON_OBJECT);

  json_value_t *inner = json_object_get(outer, "inner");
  assert(inner != NULL && inner->type == JSON_NUMBER);
  assert(inner->u.number == 42.0);

  json_free(value);
  PASS();
}

/*
 * ============================================================================
 * TEST: JSON Parser - RPC Format
 * ============================================================================
 */

static void test_json_parse_rpc_request(void) {
  TEST("JSON parse RPC request");

  const char *json =
      "{\"id\": 1, \"method\": \"getblockchaininfo\", \"params\": []}";

  json_value_t *value = NULL;
  echo_result_t res = json_parse(json, &value);

  assert(res == ECHO_OK);
  assert(value != NULL);
  assert(value->type == JSON_OBJECT);

  json_value_t *id = json_object_get(value, "id");
  json_value_t *method = json_object_get(value, "method");
  json_value_t *params = json_object_get(value, "params");

  assert(id != NULL && id->type == JSON_NUMBER);
  assert(method != NULL && method->type == JSON_STRING);
  assert(params != NULL && params->type == JSON_ARRAY);
  assert(strcmp(method->u.string, "getblockchaininfo") == 0);

  json_free(value);
  PASS();
}

static void test_json_parse_rpc_with_params(void) {
  TEST("JSON parse RPC request with params");

  const char *json =
      "{\"id\": \"test\", \"method\": \"getblock\", \"params\": "
      "[\"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\", 1]}";

  json_value_t *value = NULL;
  echo_result_t res = json_parse(json, &value);

  assert(res == ECHO_OK);
  assert(value != NULL);

  json_value_t *params = json_object_get(value, "params");
  assert(params != NULL && params->type == JSON_ARRAY);
  assert(json_array_length(params) == 2);

  json_value_t *hash = json_array_get(params, 0);
  json_value_t *verbosity = json_array_get(params, 1);

  assert(hash != NULL && hash->type == JSON_STRING);
  assert(strlen(hash->u.string) == 64); /* 64 hex chars */
  assert(verbosity != NULL && verbosity->type == JSON_NUMBER);
  assert(verbosity->u.number == 1.0);

  json_free(value);
  PASS();
}

/*
 * ============================================================================
 * TEST: JSON Builder
 * ============================================================================
 */

static void test_json_builder_string(void) {
  TEST("JSON builder string");

  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_string(&builder, "hello");
  assert(strcmp(json_builder_str(&builder), "\"hello\"") == 0);

  json_builder_free(&builder);
  PASS();
}

static void test_json_builder_number(void) {
  TEST("JSON builder number");

  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_int(&builder, 42);
  assert(strcmp(json_builder_str(&builder), "42") == 0);

  json_builder_free(&builder);
  PASS();
}

static void test_json_builder_bool(void) {
  TEST("JSON builder bool");

  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_bool(&builder, true);
  assert(strcmp(json_builder_str(&builder), "true") == 0);

  json_builder_free(&builder);
  PASS();
}

static void test_json_builder_null(void) {
  TEST("JSON builder null");

  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_null(&builder);
  assert(strcmp(json_builder_str(&builder), "null") == 0);

  json_builder_free(&builder);
  PASS();
}

static void test_json_builder_hex(void) {
  TEST("JSON builder hex");

  uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};
  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_hex(&builder, data, 4);
  assert(strcmp(json_builder_str(&builder), "\"deadbeef\"") == 0);

  json_builder_free(&builder);
  PASS();
}

static void test_json_builder_object(void) {
  TEST("JSON builder object");

  json_builder_t builder;
  json_builder_init(&builder);

  json_builder_append(&builder, "{");
  json_builder_append(&builder, "\"key\":");
  json_builder_string(&builder, "value");
  json_builder_append(&builder, "}");

  assert(strcmp(json_builder_str(&builder), "{\"key\":\"value\"}") == 0);

  json_builder_free(&builder);
  PASS();
}

/*
 * ============================================================================
 * TEST: RPC Request Parsing
 * ============================================================================
 */

static void test_rpc_request_parse_basic(void) {
  TEST("RPC request parse basic");

  const char *json =
      "{\"id\": \"1\", \"method\": \"getblockchaininfo\", \"params\": []}";

  rpc_request_t req;
  echo_result_t res = rpc_request_parse(json, &req);

  assert(res == ECHO_OK);
  assert(req.id != NULL);
  assert(strcmp(req.id, "1") == 0);
  assert(req.method != NULL);
  assert(strcmp(req.method, "getblockchaininfo") == 0);
  assert(req.params != NULL);

  rpc_request_free(&req);
  PASS();
}

static void test_rpc_request_parse_numeric_id(void) {
  TEST("RPC request parse numeric id");

  const char *json =
      "{\"id\": 42, \"method\": \"getblock\", \"params\": [\"hash\"]}";

  rpc_request_t req;
  echo_result_t res = rpc_request_parse(json, &req);

  assert(res == ECHO_OK);
  assert(req.id != NULL);
  assert(strcmp(req.id, "42") == 0);
  assert(strcmp(req.method, "getblock") == 0);

  rpc_request_free(&req);
  PASS();
}

static void test_rpc_request_parse_null_id(void) {
  TEST("RPC request parse null id");

  const char *json = "{\"id\": null, \"method\": \"test\", \"params\": []}";

  rpc_request_t req;
  echo_result_t res = rpc_request_parse(json, &req);

  assert(res == ECHO_OK);
  assert(req.id == NULL);
  assert(strcmp(req.method, "test") == 0);

  rpc_request_free(&req);
  PASS();
}

/*
 * ============================================================================
 * TEST: RPC Response Building
 * ============================================================================
 */

static void test_rpc_response_success(void) {
  TEST("RPC response success");

  json_builder_t builder;
  echo_result_t res = rpc_response_success("1", "42", &builder);

  assert(res == ECHO_OK);

  const char *response = json_builder_str(&builder);
  assert(strstr(response, "\"result\":42") != NULL);
  assert(strstr(response, "\"error\":null") != NULL);
  assert(strstr(response, "\"id\":\"1\"") != NULL);

  json_builder_free(&builder);
  PASS();
}

static void test_rpc_response_error(void) {
  TEST("RPC response error");

  json_builder_t builder;
  echo_result_t res =
      rpc_response_error("1", RPC_ERR_METHOD_NOT_FOUND, "Method not found", &builder);

  assert(res == ECHO_OK);

  const char *response = json_builder_str(&builder);
  assert(strstr(response, "\"result\":null") != NULL);
  assert(strstr(response, "\"error\":{") != NULL);
  assert(strstr(response, "\"code\":-32601") != NULL);
  assert(strstr(response, "\"message\":\"Method not found\"") != NULL);

  json_builder_free(&builder);
  PASS();
}

/*
 * ============================================================================
 * TEST: Utility Functions
 * ============================================================================
 */

static void test_hex_decode_valid(void) {
  TEST("hex decode valid");

  uint8_t out[4];
  size_t written;
  echo_result_t res = rpc_hex_decode("deadbeef", out, sizeof(out), &written);

  assert(res == ECHO_OK);
  assert(written == 4);
  assert(out[0] == 0xde);
  assert(out[1] == 0xad);
  assert(out[2] == 0xbe);
  assert(out[3] == 0xef);

  PASS();
}

static void test_hex_decode_uppercase(void) {
  TEST("hex decode uppercase");

  uint8_t out[4];
  size_t written;
  echo_result_t res = rpc_hex_decode("DEADBEEF", out, sizeof(out), &written);

  assert(res == ECHO_OK);
  assert(written == 4);
  assert(out[0] == 0xde);
  assert(out[1] == 0xad);

  PASS();
}

static void test_hex_decode_odd_length(void) {
  TEST("hex decode odd length rejected");

  uint8_t out[4];
  size_t written;
  echo_result_t res = rpc_hex_decode("abc", out, sizeof(out), &written);

  assert(res == ECHO_ERR_INVALID_FORMAT);

  PASS();
}

static void test_format_hash(void) {
  TEST("format hash (reversed byte order)");

  hash256_t hash = {0};
  /* Genesis block hash in internal byte order */
  hash.bytes[0] = 0x6f;
  hash.bytes[1] = 0xe2;
  hash.bytes[31] = 0x00;

  char out[65];
  rpc_format_hash(&hash, out);

  /* Should be reversed for display */
  assert(strlen(out) == 64);
  assert(out[0] == '0' && out[1] == '0'); /* High byte first in display */

  PASS();
}

static void test_parse_hash(void) {
  TEST("parse hash from hex");

  /* Genesis block hash in display format */
  const char *hex =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

  hash256_t hash;
  echo_result_t res = rpc_parse_hash(hex, &hash);

  assert(res == ECHO_OK);
  /* Check internal byte order (reversed from display) */
  assert(hash.bytes[31] == 0x00);
  assert(hash.bytes[0] == 0x6f);

  PASS();
}

static void test_parse_hash_invalid_length(void) {
  TEST("parse hash invalid length");

  hash256_t hash;
  echo_result_t res = rpc_parse_hash("0123456789", &hash);

  assert(res == ECHO_ERR_INVALID_FORMAT);

  PASS();
}

/*
 * ============================================================================
 * TEST: RPC Server Lifecycle
 * ============================================================================
 */

static void test_rpc_config_init(void) {
  TEST("RPC config init");

  rpc_config_t config;
  rpc_config_init(&config);

  assert(config.port == RPC_DEFAULT_PORT);
  assert(config.bind_addr == NULL);

  PASS();
}

static void test_rpc_server_create_null_node(void) {
  TEST("RPC server create with NULL node");

  rpc_config_t config;
  rpc_config_init(&config);

  rpc_server_t *server = rpc_server_create(&config, NULL);
  assert(server == NULL);

  PASS();
}

/*
 * ============================================================================
 * TEST: JSON Parser - Error Cases
 * ============================================================================
 */

static void test_json_parse_invalid_json(void) {
  TEST("JSON parse invalid JSON");

  json_value_t *value = NULL;
  echo_result_t res = json_parse("{invalid", &value);

  assert(res == ECHO_ERR_INVALID_FORMAT);
  assert(value == NULL);

  PASS();
}

static void test_json_parse_null_input(void) {
  TEST("JSON parse NULL input");

  json_value_t *value = NULL;
  echo_result_t res = json_parse(NULL, &value);

  assert(res == ECHO_ERR_NULL_PARAM);

  PASS();
}

static void test_json_parse_null_output(void) {
  TEST("JSON parse NULL output");

  echo_result_t res = json_parse("{}", NULL);

  assert(res == ECHO_ERR_NULL_PARAM);

  PASS();
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(void) {
  printf("Bitcoin Echo — RPC Interface Tests\n");
  printf("===================================\n\n");

  /* JSON Parser - Basic Types */
  test_json_parse_null();
  test_json_parse_true();
  test_json_parse_false();
  test_json_parse_integer();
  test_json_parse_negative();
  test_json_parse_float();
  test_json_parse_string();
  test_json_parse_escaped_string();
  test_json_parse_empty_string();

  /* JSON Parser - Arrays */
  test_json_parse_empty_array();
  test_json_parse_array_numbers();
  test_json_parse_mixed_array();

  /* JSON Parser - Objects */
  test_json_parse_empty_object();
  test_json_parse_simple_object();
  test_json_parse_nested_object();

  /* JSON Parser - RPC Format */
  test_json_parse_rpc_request();
  test_json_parse_rpc_with_params();

  /* JSON Builder */
  test_json_builder_string();
  test_json_builder_number();
  test_json_builder_bool();
  test_json_builder_null();
  test_json_builder_hex();
  test_json_builder_object();

  /* RPC Request Parsing */
  test_rpc_request_parse_basic();
  test_rpc_request_parse_numeric_id();
  test_rpc_request_parse_null_id();

  /* RPC Response Building */
  test_rpc_response_success();
  test_rpc_response_error();

  /* Utility Functions */
  test_hex_decode_valid();
  test_hex_decode_uppercase();
  test_hex_decode_odd_length();
  test_format_hash();
  test_parse_hash();
  test_parse_hash_invalid_length();

  /* RPC Server */
  test_rpc_config_init();
  test_rpc_server_create_null_node();

  /* JSON Parser - Error Cases */
  test_json_parse_invalid_json();
  test_json_parse_null_input();
  test_json_parse_null_output();

  printf("\n===================================\n");
  printf("Tests: %d/%d passed\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
