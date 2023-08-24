#define MAX_MUTATION_COUNT 20
#define MAX_MUTATION_VALUES_LEN 100

/*
* 可用的cmd_id和field_id
smp_pkt_field = {
    "smp_pairing_req": [
        "io_capability",
        "oob_data_flags",
        "authreq",
        "max_enc_key_size",
        "initiator_key_distribution",
        "responder_key_distribution"
    ],  # 0x01
    "smp_pairing_rsp": [
        "io_capability",
        "oob_data_flags",
        "authreq",
        "max_enc_key_size",
        "initiator_key_distribution",
        "responder_key_distribution",
    ],  # 0x02
    "smp_pairing_confirm": ["cfm_value",],  # 0x03
    "smp_pairing_random": ["random_value",],  # 0x04
    "smp_pairing_fail": ["reason"],  # 0x05
    "smp_encrypt_info": ["long_term_key",],  # 0x06
    "smp_central_ident": [
        "ediv",
        "random_value",
    ],  # 0x07
    "smp_ident_info": ["id_resolving_key",],  # 0x08
    "smp_ident_addr_info": [
        "address_type",
        "bd_addr",
    ],  # 0x09
    "smp_public_key": ["long_term_key",],  # 0x0c
    "smp_dhkey_check": ["dhkey_check",],  # 0x0d
}
*/

/*
* mutation结构体，代表一个mutation动作，cmd_id表示报文类型，field_id表示报文字段的序号
* eg. {0x01, 0x00}表示BT_SMP_CMD_PAIRING_REQ类型的报文的第1个字段
* 即BT_SMP_CMD_PAIRING_REQ->io_capability，mutation的值在BlesserInstruction的mutation_values字段中保存
*/
struct mutation{
    char cmd_id;
    char field_id;
};

/*
* BlesserInstruction结构体，表示fontend的一次Instruction，包含多个mutation动作
* mutation_count: 该instruction包含多少个mutation
* mutations[]: mutations的数组
* mutation_values[]: mutations的值
*/
struct BlesserInstruction{
    char mutation_count;
    struct mutation mutations[MAX_MUTATION_COUNT];
    char mutation_values[MAX_MUTATION_VALUES_LEN];
};
