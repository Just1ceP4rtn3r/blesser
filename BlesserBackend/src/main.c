/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/drivers/uart.h>
#include "../Include/Instruction.h"

/*
* func parse()
* 参数: struct Instruction *instruction, uint8_t *recv, int len
*       Instruction类型结构体的指针,      uart收到的数据的指针, uart收到的数据的长度
* 返回值: 函数执行完后返回0
*/
int parse(struct BlesserInstruction *instruction, uint8_t *recv, int len){
    instruction->mutation_count = recv[0];
    int i = 0;
    int j = 1;
    while(i < instruction->mutation_count && j < len){
        instruction->mutations[i].cmd_id = recv[j++];
        instruction->mutations[i++].field_id = recv[j++];
    }
    for(i=0; j < len; i++, j++){
        instruction->mutation_values[i] = recv[j];
    }
    return 0;
}

struct BlesserInstruction CMD_FROM_BLESSER;

//uart config
/* 1000 msec = 1 sec */
// #define SLEEP_TIME_MS   1000

/* Define the size of the receive buffer */
#define RECEIVE_BUFF_SIZE 100

/* Define the receiving timeout period */
#define RECEIVE_TIMEOUT 100
/* Get the device pointer of the UART hardware */
const struct device *uart= DEVICE_DT_GET(DT_NODELABEL(uart0));

/* Define the receive buffer */
static uint8_t rx_buf[RECEIVE_BUFF_SIZE] = {0};
static uint8_t app_buf[RECEIVE_BUFF_SIZE] = {0};

static void start_scan(void);

static struct bt_conn *default_conn;

uint8_t uart_send_func(uint8_t *packet, int len){
	int err = uart_tx(uart, packet, len, SYS_FOREVER_US);
	return err;
}
K_MUTEX_DEFINE(app_buf_mutex);

// flag to indicate if app_buf have data
bool recv_flag = false;
// len to indicate the length of the data in app_buf
int recv_len = 0;

void thread_blesser_backend(void){
	while (true)
	{
		k_mutex_lock(&app_buf_mutex, K_FOREVER);
		if(recv_flag){
			if(default_conn){
				parse(&CMD_FROM_BLESSER, app_buf, recv_len);
				// do fuzz with instruction
                bt_conn_set_security(default_conn, BT_SECURITY_L2);
				recv_flag = 0;
			} else {
				printk("[ERROR]: connection is NULL\n");
			}
		}
		k_mutex_unlock(&app_buf_mutex);
        k_msleep(100);
	}

}
K_THREAD_DEFINE(thread_blesser_backend_id, 1024, thread_blesser_backend, NULL, NULL, NULL, 10, 0, 0);
static void uart_cb(const struct device *dev, struct uart_event *evt, void *user_data)
{
	switch (evt->type) {
	case UART_RX_RDY:
        printk("UART_RX_RDY event\nUART_RX_LEN: %d\n", evt->data.rx.len);
        memcpy(app_buf, evt->data.rx.buf + evt->data.rx.offset, evt->data.rx.len);
        //memset(app_buf + evt->data.rx.len, 0, 1);
        k_mutex_lock(&app_buf_mutex, K_FOREVER);
        recv_flag = 1;
		recv_len = evt->data.rx.len;
        uart_rx_disable(uart);
        k_mutex_unlock(&app_buf_mutex);
	    break;

	case UART_RX_DISABLED:
    	uart_rx_enable(uart, rx_buf, sizeof rx_buf, RECEIVE_TIMEOUT);
		break;

	default:
		break;
	}
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	int err;

	if (default_conn) {
		return;
	}

	/* We're only interested in connectable events */
	if (type != BT_GAP_ADV_TYPE_ADV_IND &&
	    type != BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	printk("Device found: %s (RSSI %d)\n", addr_str, rssi);

	/* connect only to devices in close proximity */
	if (rssi < -70) {
		return;
	}

	if (bt_le_scan_stop()) {
		return;
	}

	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
				BT_LE_CONN_PARAM_DEFAULT, &default_conn);
	if (err) {
		printk("Create conn to %s failed (%u)\n", addr_str, err);
		start_scan();
	}
}

static void start_scan(void)
{
	int err;

	/* This demo doesn't require active scan */
	err = bt_le_scan_start(BT_LE_SCAN_PASSIVE, device_found);
	if (err) {
		printk("Scanning failed to start (err %d)\n", err);
		return;
	}

	printk("Scanning successfully started\n");
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		printk("Failed to connect to %s (%u)\n", addr, err);

		bt_conn_unref(default_conn);
		default_conn = NULL;

		start_scan();
		return;
	}

	if (conn != default_conn) {
		return;
	}

	printk("Connected: %s\n", addr);

	//bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	if (conn != default_conn) {
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
	if (!device_is_ready(uart)){
		printk("UART device not ready\n");
		return;
	}
	/* Register the UART callback function */
	err = uart_callback_set(uart, uart_cb, NULL);
	if (err) {
		printk("Uart set cb failed (err %d)", err);
		return;
	}
	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

    uart_rx_enable(uart, rx_buf, sizeof rx_buf, RECEIVE_TIMEOUT);
	start_scan();
}
