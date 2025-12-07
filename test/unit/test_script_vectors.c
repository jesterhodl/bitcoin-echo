/*
 * Bitcoin Echo — Script Test Vectors
 *
 * Test harness for Bitcoin Core's script_tests.json test vectors.
 * Parses the human-readable script format and executes tests.
 *
 * Build once. Build right. Stop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "script.h"
#include "tx.h"
#include "ripemd160.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_skipped = 0;

/*
 * Maximum sizes for parsing.
 */
#define MAX_SCRIPT_SIZE   10000
#define MAX_LINE_SIZE     16384
#define MAX_TOKEN_SIZE    1024

/*
 * Opcode name to value mapping.
 */
typedef struct {
    const char *name;
    uint8_t     value;
} opcode_map_t;

static const opcode_map_t opcode_names[] = {
    /* Push value */
    {"0", OP_0}, {"FALSE", OP_0},
    {"1NEGATE", OP_1NEGATE},
    {"1", OP_1}, {"TRUE", OP_1},
    {"2", OP_2}, {"3", OP_3}, {"4", OP_4}, {"5", OP_5},
    {"6", OP_6}, {"7", OP_7}, {"8", OP_8}, {"9", OP_9},
    {"10", OP_10}, {"11", OP_11}, {"12", OP_12}, {"13", OP_13},
    {"14", OP_14}, {"15", OP_15}, {"16", OP_16},

    /* Flow control */
    {"NOP", OP_NOP},
    {"VER", OP_VER},
    {"IF", OP_IF}, {"NOTIF", OP_NOTIF},
    {"VERIF", OP_VERIF}, {"VERNOTIF", OP_VERNOTIF},
    {"ELSE", OP_ELSE}, {"ENDIF", OP_ENDIF},
    {"VERIFY", OP_VERIFY}, {"RETURN", OP_RETURN},

    /* Stack */
    {"TOALTSTACK", OP_TOALTSTACK}, {"FROMALTSTACK", OP_FROMALTSTACK},
    {"2DROP", OP_2DROP}, {"2DUP", OP_2DUP}, {"3DUP", OP_3DUP},
    {"2OVER", OP_2OVER}, {"2ROT", OP_2ROT}, {"2SWAP", OP_2SWAP},
    {"IFDUP", OP_IFDUP}, {"DEPTH", OP_DEPTH}, {"DROP", OP_DROP},
    {"DUP", OP_DUP}, {"NIP", OP_NIP}, {"OVER", OP_OVER},
    {"PICK", OP_PICK}, {"ROLL", OP_ROLL}, {"ROT", OP_ROT},
    {"SWAP", OP_SWAP}, {"TUCK", OP_TUCK},

    /* Splice */
    {"CAT", OP_CAT}, {"SUBSTR", OP_SUBSTR}, {"LEFT", OP_LEFT},
    {"RIGHT", OP_RIGHT}, {"SIZE", OP_SIZE},

    /* Bitwise */
    {"INVERT", OP_INVERT}, {"AND", OP_AND}, {"OR", OP_OR}, {"XOR", OP_XOR},
    {"EQUAL", OP_EQUAL}, {"EQUALVERIFY", OP_EQUALVERIFY},
    {"RESERVED1", OP_RESERVED1}, {"RESERVED2", OP_RESERVED2},
    {"RESERVED", OP_RESERVED},

    /* Arithmetic */
    {"1ADD", OP_1ADD}, {"1SUB", OP_1SUB},
    {"2MUL", OP_2MUL}, {"2DIV", OP_2DIV},
    {"NEGATE", OP_NEGATE}, {"ABS", OP_ABS},
    {"NOT", OP_NOT}, {"0NOTEQUAL", OP_0NOTEQUAL},
    {"ADD", OP_ADD}, {"SUB", OP_SUB},
    {"MUL", OP_MUL}, {"DIV", OP_DIV}, {"MOD", OP_MOD},
    {"LSHIFT", OP_LSHIFT}, {"RSHIFT", OP_RSHIFT},
    {"BOOLAND", OP_BOOLAND}, {"BOOLOR", OP_BOOLOR},
    {"NUMEQUAL", OP_NUMEQUAL}, {"NUMEQUALVERIFY", OP_NUMEQUALVERIFY},
    {"NUMNOTEQUAL", OP_NUMNOTEQUAL},
    {"LESSTHAN", OP_LESSTHAN}, {"GREATERTHAN", OP_GREATERTHAN},
    {"LESSTHANOREQUAL", OP_LESSTHANOREQUAL},
    {"GREATERTHANOREQUAL", OP_GREATERTHANOREQUAL},
    {"MIN", OP_MIN}, {"MAX", OP_MAX}, {"WITHIN", OP_WITHIN},

    /* Crypto */
    {"RIPEMD160", OP_RIPEMD160}, {"SHA1", OP_SHA1}, {"SHA256", OP_SHA256},
    {"HASH160", OP_HASH160}, {"HASH256", OP_HASH256},
    {"CODESEPARATOR", OP_CODESEPARATOR},
    {"CHECKSIG", OP_CHECKSIG}, {"CHECKSIGVERIFY", OP_CHECKSIGVERIFY},
    {"CHECKMULTISIG", OP_CHECKMULTISIG},
    {"CHECKMULTISIGVERIFY", OP_CHECKMULTISIGVERIFY},

    /* Locktime */
    {"NOP1", OP_NOP1},
    {"CHECKLOCKTIMEVERIFY", OP_CHECKLOCKTIMEVERIFY}, {"CLTV", OP_CHECKLOCKTIMEVERIFY},
    {"CHECKSEQUENCEVERIFY", OP_CHECKSEQUENCEVERIFY}, {"CSV", OP_CHECKSEQUENCEVERIFY},
    {"NOP4", OP_NOP4}, {"NOP5", OP_NOP5}, {"NOP6", OP_NOP6},
    {"NOP7", OP_NOP7}, {"NOP8", OP_NOP8}, {"NOP9", OP_NOP9}, {"NOP10", OP_NOP10},

    /* Taproot */
    {"CHECKSIGADD", OP_CHECKSIGADD},

    {NULL, 0}
};

/*
 * Look up opcode by name.
 */
static int lookup_opcode(const char *name, uint8_t *value)
{
    for (const opcode_map_t *op = opcode_names; op->name != NULL; op++) {
        if (strcasecmp(name, op->name) == 0) {
            *value = op->value;
            return 1;
        }
    }
    return 0;
}

/*
 * Parse hex digit.
 */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Encode a number as minimal script bytes.
 */
static size_t encode_num(int64_t num, uint8_t *out)
{
    if (num == 0) {
        return 0;  /* Empty byte array */
    }

    int negative = (num < 0);
    uint64_t abs_num = negative ? -num : num;

    /* Encode in little-endian */
    size_t len = 0;
    while (abs_num > 0) {
        out[len++] = abs_num & 0xFF;
        abs_num >>= 8;
    }

    /* Add sign bit if needed */
    if (out[len - 1] & 0x80) {
        out[len++] = negative ? 0x80 : 0x00;
    } else if (negative) {
        out[len - 1] |= 0x80;
    }

    return len;
}

/*
 * Assemble a human-readable script into bytes.
 * Returns the length of the assembled script, or -1 on error.
 */
static int assemble_script(const char *script_str, uint8_t *out, size_t max_len)
{
    const char *p = script_str;
    size_t pos = 0;

    while (*p) {
        /* Skip whitespace */
        while (*p && isspace(*p)) p++;
        if (!*p) break;

        /* Check for hex bytes: 0xAB or 0xABCD... */
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            p += 2;
            uint8_t bytes[MAX_TOKEN_SIZE];
            size_t byte_count = 0;

            while (hex_digit(*p) >= 0 && hex_digit(p[1]) >= 0) {
                bytes[byte_count++] = (hex_digit(p[0]) << 4) | hex_digit(p[1]);
                p += 2;
            }

            /* Copy bytes to output */
            for (size_t i = 0; i < byte_count && pos < max_len; i++) {
                out[pos++] = bytes[i];
            }
            continue;
        }

        /* Check for string literal: 'text' */
        if (*p == '\'') {
            p++;
            const char *start = p;
            while (*p && *p != '\'') p++;
            size_t str_len = p - start;
            if (*p == '\'') p++;

            /* Empty string pushes OP_0 */
            if (str_len == 0) {
                if (pos < max_len) out[pos++] = OP_0;
                continue;
            }

            /* Add push opcode */
            if (str_len <= 75) {
                if (pos < max_len) out[pos++] = (uint8_t)str_len;
            } else if (str_len <= 255) {
                if (pos < max_len) out[pos++] = OP_PUSHDATA1;
                if (pos < max_len) out[pos++] = (uint8_t)str_len;
            } else if (str_len <= 65535) {
                if (pos < max_len) out[pos++] = OP_PUSHDATA2;
                if (pos < max_len) out[pos++] = str_len & 0xFF;
                if (pos < max_len) out[pos++] = (str_len >> 8) & 0xFF;
            } else {
                return -1;
            }

            /* Copy string bytes */
            for (size_t i = 0; i < str_len && pos < max_len; i++) {
                out[pos++] = start[i];
            }
            continue;
        }

        /* Parse token */
        char token[MAX_TOKEN_SIZE];
        size_t token_len = 0;
        while (*p && !isspace(*p) && token_len < MAX_TOKEN_SIZE - 1) {
            token[token_len++] = *p++;
        }
        token[token_len] = '\0';

        if (token_len == 0) continue;

        /* Check for opcode name */
        uint8_t opcode;
        if (lookup_opcode(token, &opcode)) {
            if (pos < max_len) out[pos++] = opcode;
            continue;
        }

        /* Check for decimal number */
        char *endptr;
        long long num = strtoll(token, &endptr, 10);
        if (*endptr == '\0') {
            /* It's a number - encode it */
            if (num == 0) {
                if (pos < max_len) out[pos++] = OP_0;
            } else if (num >= 1 && num <= 16) {
                if (pos < max_len) out[pos++] = OP_1 + (num - 1);
            } else if (num == -1) {
                if (pos < max_len) out[pos++] = OP_1NEGATE;
            } else {
                /* Encode as push */
                uint8_t num_bytes[9];
                size_t num_len = encode_num(num, num_bytes);
                if (num_len <= 75) {
                    if (pos < max_len) out[pos++] = (uint8_t)num_len;
                } else {
                    if (pos < max_len) out[pos++] = OP_PUSHDATA1;
                    if (pos < max_len) out[pos++] = (uint8_t)num_len;
                }
                for (size_t i = 0; i < num_len && pos < max_len; i++) {
                    out[pos++] = num_bytes[i];
                }
            }
            continue;
        }

        /* Unknown token */
        fprintf(stderr, "Unknown token: %s\n", token);
        return -1;
    }

    return (int)pos;
}

/*
 * Parse verification flags from string.
 */
static uint32_t parse_flags(const char *flags_str)
{
    uint32_t flags = 0;

    if (strstr(flags_str, "P2SH")) flags |= SCRIPT_VERIFY_P2SH;
    if (strstr(flags_str, "STRICTENC")) flags |= SCRIPT_VERIFY_STRICTENC;
    if (strstr(flags_str, "DERSIG")) flags |= SCRIPT_VERIFY_DERSIG;
    if (strstr(flags_str, "LOW_S")) flags |= SCRIPT_VERIFY_LOW_S;
    if (strstr(flags_str, "NULLDUMMY")) flags |= SCRIPT_VERIFY_NULLDUMMY;
    if (strstr(flags_str, "SIGPUSHONLY")) flags |= SCRIPT_VERIFY_SIGPUSHONLY;
    if (strstr(flags_str, "MINIMALDATA")) flags |= SCRIPT_VERIFY_MINIMALDATA;
    if (strstr(flags_str, "DISCOURAGE_UPGRADABLE_NOPS"))
        flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    if (strstr(flags_str, "CLEANSTACK")) flags |= SCRIPT_VERIFY_CLEANSTACK;
    if (strstr(flags_str, "CHECKLOCKTIMEVERIFY"))
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    if (strstr(flags_str, "CHECKSEQUENCEVERIFY"))
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    if (strstr(flags_str, "WITNESS")) flags |= SCRIPT_VERIFY_WITNESS;
    if (strstr(flags_str, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"))
        flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    if (strstr(flags_str, "MINIMALIF")) flags |= SCRIPT_VERIFY_MINIMALIF;
    if (strstr(flags_str, "NULLFAIL")) flags |= SCRIPT_VERIFY_NULLFAIL;
    if (strstr(flags_str, "WITNESS_PUBKEYTYPE"))
        flags |= SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
    if (strstr(flags_str, "CONST_SCRIPTCODE"))
        flags |= SCRIPT_VERIFY_CONST_SCRIPTCODE;
    if (strstr(flags_str, "TAPROOT")) flags |= SCRIPT_VERIFY_TAPROOT;

    return flags;
}

/*
 * Run a single test vector.
 */
static void run_test(const char *scriptsig_str, const char *scriptpubkey_str,
                     const char *flags_str, const char *expected_str,
                     const char *comment)
{
    tests_run++;

    /* Assemble scripts */
    uint8_t scriptsig[MAX_SCRIPT_SIZE];
    uint8_t scriptpubkey[MAX_SCRIPT_SIZE];

    int sig_len = assemble_script(scriptsig_str, scriptsig, MAX_SCRIPT_SIZE);
    int pubkey_len = assemble_script(scriptpubkey_str, scriptpubkey, MAX_SCRIPT_SIZE);

    if (sig_len < 0 || pubkey_len < 0) {
        tests_skipped++;
        return;
    }

    /* Parse flags */
    uint32_t flags = parse_flags(flags_str);

    /* Skip witness-only tests for now (require witness data) */
    if (flags & SCRIPT_VERIFY_WITNESS) {
        tests_skipped++;
        return;
    }

    /* Create context */
    script_context_t ctx;
    script_context_init(&ctx, flags);

    /* Create minimal transaction */
    tx_t tx;
    tx_init(&tx);
    tx.version = 1;
    tx.locktime = 0;
    tx.input_count = 1;
    tx.inputs = calloc(1, sizeof(tx_input_t));
    tx.inputs[0].sequence = TX_SEQUENCE_FINAL - 1;  /* Non-final for locktime tests */
    tx.output_count = 1;
    tx.outputs = calloc(1, sizeof(tx_output_t));
    tx.outputs[0].value = 0;

    script_set_tx_context(&ctx, &tx, 0, 0, scriptpubkey, pubkey_len);

    /* Execute scriptSig */
    echo_result_t res = script_execute(&ctx, scriptsig, sig_len);
    if (res != ECHO_OK) {
        goto check_result;
    }

    /*
     * Clear the altstack between scriptSig and scriptPubKey.
     * The altstack is NOT shared between the two - this is consensus behavior.
     */
    stack_free(&ctx.altstack);
    stack_init(&ctx.altstack);

    /*
     * Check for P2SH - we need to save the stack state before executing
     * scriptPubKey because we'll need the serialized redeem script.
     */
    uint8_t redeem_script[MAX_SCRIPT_SIZE];
    size_t redeem_len = 0;
    echo_bool_t is_p2sh = ECHO_FALSE;
    hash160_t p2sh_hash;

    if ((flags & SCRIPT_VERIFY_P2SH) && script_is_p2sh(scriptpubkey, pubkey_len, &p2sh_hash)) {
        is_p2sh = ECHO_TRUE;

        /*
         * BIP-16: For P2SH, scriptSig must be push-only.
         * Check before we continue with execution.
         */
        if (!script_is_push_only(scriptsig, sig_len)) {
            ctx.error = SCRIPT_ERR_SIG_PUSHONLY;
            res = ECHO_ERR_SCRIPT_ERROR;
            goto check_result;
        }

        /* Save the top stack element (serialized redeem script) */
        const stack_element_t *top;
        if (stack_peek(&ctx.stack, &top) == ECHO_OK && top->len < MAX_SCRIPT_SIZE) {
            memcpy(redeem_script, top->data, top->len);
            redeem_len = top->len;
        }
    }

    /* Execute scriptPubKey */
    res = script_execute(&ctx, scriptpubkey, pubkey_len);
    if (res != ECHO_OK) {
        goto check_result;
    }

    /* P2SH evaluation: execute the redeem script */
    if (is_p2sh && redeem_len > 0) {
        /* Verify the serialized script hashes correctly */
        uint8_t script_hash[20];
        hash160(redeem_script, redeem_len, script_hash);
        if (memcmp(script_hash, p2sh_hash.bytes, 20) == 0) {
            /* Pop the redeem script from stack before executing it */
            stack_element_t elem;
            stack_pop(&ctx.stack, &elem);
            if (elem.data) free(elem.data);

            /* Execute the redeem script */
            res = script_execute(&ctx, redeem_script, redeem_len);
        }
    }

check_result:
    {
        echo_bool_t expected_ok = (strcmp(expected_str, "OK") == 0);
        echo_bool_t actual_ok = (res == ECHO_OK);

        /* For successful scripts, check final stack state */
        if (actual_ok) {
            /* Stack must be non-empty and top must be true */
            if (stack_empty(&ctx.stack)) {
                actual_ok = ECHO_FALSE;
            } else {
                const stack_element_t *top;
                stack_peek(&ctx.stack, &top);
                if (!script_bool(top->data, top->len)) {
                    actual_ok = ECHO_FALSE;
                }
            }

            /* CLEANSTACK requires exactly one element */
            if (actual_ok && (flags & SCRIPT_VERIFY_CLEANSTACK)) {
                if (stack_size(&ctx.stack) != 1) {
                    actual_ok = ECHO_FALSE;
                }
            }
        }

        if (expected_ok == actual_ok) {
            tests_passed++;
        } else {
            printf("[FAIL] %s\n", comment ? comment : "");
            printf("  scriptSig: %s\n", scriptsig_str);
            printf("  scriptPubKey: %s\n", scriptpubkey_str);
            printf("  flags: %s\n", flags_str);
            printf("  expected: %s, got: %s\n",
                   expected_str,
                   actual_ok ? "OK" : script_error_string(ctx.error));
        }
    }

    script_context_free(&ctx);
    tx_free(&tx);
}

/*
 * Extract JSON string value (very simple parser).
 * Returns pointer past closing quote, or NULL on error.
 */
static const char *extract_string(const char *p, char *out, size_t max_len)
{
    if (*p != '"') return NULL;
    p++;

    size_t len = 0;
    while (*p && *p != '"' && len < max_len - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[len++] = '\n'; break;
                case 't': out[len++] = '\t'; break;
                case '"': out[len++] = '"'; break;
                case '\\': out[len++] = '\\'; break;
                default: out[len++] = *p; break;
            }
        } else {
            out[len++] = *p;
        }
        p++;
    }
    out[len] = '\0';

    if (*p == '"') p++;
    return p;
}

/*
 * Parse and run tests from JSON file.
 */
static void run_tests_from_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Cannot open test file: %s\n", filename);
        return;
    }

    char line[MAX_LINE_SIZE];
    char scriptsig[MAX_LINE_SIZE];
    char scriptpubkey[MAX_LINE_SIZE];
    char flags[256];
    char expected[64];
    char comment[MAX_LINE_SIZE];

    while (fgets(line, sizeof(line), f)) {
        /* Skip comment lines and empty lines */
        const char *p = line;
        while (*p && isspace(*p)) p++;

        if (*p != '[') continue;
        p++;

        /* Check for comment-only line (starts with single string) */
        while (*p && isspace(*p)) p++;
        if (*p != '"') continue;

        /* Parse first field - could be witness data or scriptSig */
        p = extract_string(p, scriptsig, sizeof(scriptsig));
        if (!p) continue;

        while (*p && (*p == ',' || isspace(*p))) p++;

        /* If we find another string, it's scriptPubKey */
        if (*p == '"') {
            p = extract_string(p, scriptpubkey, sizeof(scriptpubkey));
            if (!p) continue;
        } else if (*p == '[') {
            /* Witness data - skip for now */
            continue;
        } else {
            continue;
        }

        while (*p && (*p == ',' || isspace(*p))) p++;

        /* Parse flags */
        if (*p != '"') continue;
        p = extract_string(p, flags, sizeof(flags));
        if (!p) continue;

        while (*p && (*p == ',' || isspace(*p))) p++;

        /* Parse expected result */
        if (*p != '"') continue;
        p = extract_string(p, expected, sizeof(expected));
        if (!p) continue;

        /* Optional comment */
        comment[0] = '\0';
        while (*p && (*p == ',' || isspace(*p))) p++;
        if (*p == '"') {
            extract_string(p, comment, sizeof(comment));
        }

        /* Run the test */
        run_test(scriptsig, scriptpubkey, flags, expected, comment);
    }

    fclose(f);
}

int main(int argc, char *argv[])
{
    printf("Bitcoin Echo — Script Test Vectors\n");
    printf("===================================\n\n");

    const char *test_file = "test/vectors/script_tests.json";
    if (argc > 1) {
        test_file = argv[1];
    }

    printf("Loading tests from: %s\n\n", test_file);
    run_tests_from_file(test_file);

    printf("\n===================================\n");
    printf("Tests: %d run, %d passed, %d skipped\n",
           tests_run, tests_passed, tests_skipped);

    int failed = tests_run - tests_passed - tests_skipped;
    if (failed > 0) {
        printf("FAILURES: %d\n", failed);
    }

    return (tests_passed == tests_run - tests_skipped) ? 0 : 1;
}
