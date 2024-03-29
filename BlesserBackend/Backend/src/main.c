/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/types.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/byteorder.h>
#include "../Include/Instruction.h"

/*
 * func parse()
 * 参数: struct Instruction *instruction, uint8_t *recv, int len
 *       Instruction类型结构体的指针,      uart收到的数据的指针, uart收到的数据的长度
 * 返回值: 函数执行完后返回0
 */
int parse(struct BlesserInstruction* instruction, uint8_t* recv, int len)
{
    size_t offset = 0;
    instruction->mutation_count = 0;
    short mapper[16][6] = {{}, {1, 1, 1, 1, 1, 1}, {1, 1, 1, 1, 1, 1}, {16}, {16}, {1}, {16}, {2, 8}, {16}, {1, 6}, {16}, {1}, {64}, {16}, {1}, {}};
    while (offset < len)
    {
        instruction->mutations[instruction->mutation_count].cmd_id = *(char*)(recv + offset);
        instruction->mutations[instruction->mutation_count].field_id = *(char*)(recv + offset + 1);
        int value_size = mapper[instruction->mutations[instruction->mutation_count].cmd_id][instruction->mutations[instruction->mutation_count].field_id];

        printk("%u, %u, ", instruction->mutations[instruction->mutation_count].cmd_id, instruction->mutations[instruction->mutation_count].field_id);
        // for (int i = 0; i < value_size; i++)
        // {
        //     printk("%x ", instruction->mutations[instruction->mutation_count].mutation_values[i]);
        // }
        printk("\n");
        memcpy(instruction->mutations[instruction->mutation_count].mutation_values, recv + offset + 2, value_size);



        instruction->mutation_count++;

        offset += 1 + 1 + value_size;
    }
    return 0;
}

struct BlesserInstruction CMD_FROM_BLESSER;
uint8_t RESP_size = 0;
uint8_t RESP_idx = 0;
struct ResponsePacket RESP[20];

// uart config
/* 1000 msec = 1 sec */
// #define SLEEP_TIME_MS   1000

/* Define the size of the receive buffer */
#define RECEIVE_BUFF_SIZE 100

/* Define the receiving timeout period */
#define RECEIVE_TIMEOUT 100
/* Get the device pointer of the UART hardware */
const struct device* uart = DEVICE_DT_GET(DT_NODELABEL(uart0));

/* Define the receive buffer */
static uint8_t rx_buf[RECEIVE_BUFF_SIZE] = {0};
uint8_t app_buf[RECEIVE_BUFF_SIZE] = {0};
uint8_t app_buf_size = 0;

static void start_scan(void);

static struct bt_conn* default_conn;

uint8_t uart_send_func(uint8_t* packet, int len)
{
    int err = uart_tx(uart, packet, len, SYS_FOREVER_US);
    return err;
}
K_MUTEX_DEFINE(app_buf_mutex);

// flag to indicate if app_buf have data
bool recv_flag = false;
// len to indicate the length of the data in app_buf
int recv_len = 0;

void thread_blesser_backend(void)
{
    while (true)
    {
        k_mutex_lock(&app_buf_mutex, K_FOREVER);
        if (recv_flag)
        {
            printk("recv_len: %d\n", recv_len);
            for (int i = 0; i < recv_len; i++)
            {
                printk("%x ", app_buf[i]);
            }
            if (default_conn)
            {
                if (app_buf[0] == 0x01 && recv_len == 1)
                {                
                    // if app_buf = "1"
                    // bt_conn_send_smp_packet(default_conn);
                    int xx = bt_conn_disconnect(default_conn,BT_HCI_ERR_AUTH_FAIL);
                    RESP_size = 0;
                    RESP_idx = 0;
                    // printk("%d\n", xx);
                    // bt_conn_auth_cancel(default_conn);
                }
                else if (app_buf[0] == 0xff && recv_len == 1)
                {               
                    if(RESP_size >0 && RESP_idx < RESP_size){
                        int err = uart_tx(uart, RESP[RESP_idx].buf,RESP[RESP_idx].packet_size, SYS_FOREVER_US);
                        RESP_idx++;
                    }
                }
                else if (app_buf[0] == 0x00 && recv_len == 1)
                {
                    bt_conn_set_security(default_conn, BT_SECURITY_L2);
                }
                else
                {
                    // if app_buf = "010000...."
                    parse(&CMD_FROM_BLESSER, app_buf, recv_len);
                    // do fuzz with instruction
                    bt_conn_set_security(default_conn, BT_SECURITY_L2);
                }

                recv_flag = 0;
            }
            else
            {
                printk("[ERROR]: connection is NULL\n");
            }
        }
        k_mutex_unlock(&app_buf_mutex);
        k_msleep(100);
    }
}
K_THREAD_DEFINE(thread_blesser_backend_id, 1024, thread_blesser_backend, NULL, NULL, NULL, 10, 0, 0);
static void uart_cb(const struct device* dev, struct uart_event* evt, void* user_data)
{
    switch (evt->type)
    {
    case UART_RX_RDY:
        // printk("UART_RX_RDY event\nUART_RX_LEN: %d\n", evt->data.rx.len);
        memcpy(app_buf+app_buf_size, evt->data.rx.buf + evt->data.rx.offset, evt->data.rx.len);
        app_buf_size += evt->data.rx.len;

        k_mutex_lock(&app_buf_mutex, K_FOREVER);
        if(app_buf_size > 4){
            char tail[4] = {0};
            memcpy(tail, app_buf+app_buf_size-4, 4);

            if(tail[0] == 0x66 && tail[1] ==0x78 && tail[2] == 0x78 && tail[3] == 0x6b )
            {
                        // memset(app_buf + evt->data.rx.len, 0, 1);
                
                recv_flag = 1;
                recv_len = app_buf_size-4;
                uart_rx_disable(uart);
                
            }

        }
        k_mutex_unlock(&app_buf_mutex);
        break;

    case UART_RX_DISABLED:
        app_buf_size = 0;
        uart_rx_enable(uart, rx_buf, sizeof rx_buf, RECEIVE_TIMEOUT);
        break;

    case UART_TX_DONE:
        if(RESP_size >0 && RESP_idx < RESP_size){
            int err = uart_tx(uart, RESP[RESP_idx].buf,RESP[RESP_idx].packet_size, SYS_FOREVER_US);
            RESP_idx++;
        }
        break;

    default:
        break;
    }
}

static void device_found(const bt_addr_le_t* addr, int8_t rssi, uint8_t type, struct net_buf_simple* ad)
{
    char addr_str[BT_ADDR_LE_STR_LEN];
    int  err;

    if (default_conn)
    {
        return;
    }

    /* We're only interested in connectable events */
    if (type != BT_GAP_ADV_TYPE_ADV_IND && type != BT_GAP_ADV_TYPE_ADV_DIRECT_IND)
    {
        return;
    }

    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
    printk("Device found: %s (RSSI %d)\n", addr_str, rssi);

    /* connect only to devices in close proximity */
    // if (rssi < -70) {
    // 	return;
    // }

    if (strcmp(addr_str, "F4:5A:DE:3A:CC:5F (random)"))
    // if (strcmp(addr_str, "50:e7:b7:f4:de:a9 (random)"))
    {
        printk("Not same\n");
        return;
    }

    if (bt_le_scan_stop())
    {
        return;
    }

    err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, BT_LE_CONN_PARAM_DEFAULT, &default_conn);
    if (err)
    {
        printk("Create conn to %s failed (%u)\n", addr_str, err);
        start_scan();
    }
}

static void start_scan(void)
{
    int err;

    /* This demo doesn't require active scan */
    err = bt_le_scan_start(BT_LE_SCAN_PASSIVE, device_found);
    if (err)
    {
        printk("Scanning failed to start (err %d)\n", err);
        return;
    }

    printk("Scanning successfully started\n");
}

static void connected(struct bt_conn* conn, uint8_t err)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    if (err)
    {
        printk("Failed to connect to %s (%u)\n", addr, err);

        bt_conn_unref(default_conn);
        default_conn = NULL;

        start_scan();
        return;
    }

    if (conn != default_conn)
    {
        return;
    }

    printk("Connected: %s\n", addr);

    // bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

static void disconnected(struct bt_conn* conn, uint8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];

    if (conn != default_conn)
    {
        return;
    }

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    printk("Disconnected: %s (reason 0x%02x)\n", addr, reason);

    bt_conn_unref(default_conn);
    default_conn = NULL;

    start_scan();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};

void main(void)
{
    int err;
    /* Verify that the UART device is ready */
    if (!device_is_ready(uart))
    {
        printk("UART device not ready\n");
        return;
    }
    /* Register the UART callback function */
    err = uart_callback_set(uart, uart_cb, NULL);
    if (err)
    {
        printk("Uart set cb failed (err %d)", err);
        return;
    }
    err = bt_enable(NULL);
    if (err)
    {
        printk("Bluetooth init failed (err %d)\n", err);
        return;
    }

    printk("Bluetooth initialized\n");

    uart_rx_enable(uart, rx_buf, sizeof rx_buf, RECEIVE_TIMEOUT);
    start_scan();
}
