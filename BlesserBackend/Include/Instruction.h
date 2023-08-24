#define uint8_t char
#define MAX_MUTATION_COUNT 20
#define MAX_MUTATION_VALUES_LEN 100

/*
* mutation结构体，代表一个mutation动作，cmd_id表示报文类型，field_id表示报文字段的序号
* eg. {0x01, 0x00}表示BT_SMP_CMD_PAIRING_REQ类型的报文的第1个字段
* 即BT_SMP_CMD_PAIRING_REQ->io_capability，mutation的值在BlesserInstruction的mutation_values字段中保存
*/
struct mutation{
    uint8_t cmd_id;
    uint8_t field_id;
};

/*
* BlesserInstruction结构体，表示fontend的一次Instruction，包含多个mutation动作
* mutation_count: 该instruction包含多少个mutation
* mutations[]: mutations的数组
* mutation_values[]: mutations的值
*/
struct BlesserInstruction{
    uint8_t mutation_count;
    struct mutation mutations[MAX_MUTATION_COUNT];
    uint8_t mutation_values[MAX_MUTATION_VALUES_LEN];
};
