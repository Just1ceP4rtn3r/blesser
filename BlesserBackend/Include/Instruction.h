#define uint8_t char
#define MAX_MUTATION_COUNT 20
#define MAX_MUTATION_VALUES_LEN 100

struct mutation{
    uint8_t cmd_id;
    uint8_t filed_id;
}

struct Instruction{
    uint8_t mutation_count;
    struct mutation mutations[MAX_MUTATION_COUNT];
    uint8_t mutation_values[MAX_MUTATION_VALUES_LEN];
};
