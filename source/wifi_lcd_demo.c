/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include "FreeRTOS.h"
#include "task.h"

#include "fsl_debug_console.h"
#include "lvgl_support.h"
#include "pin_mux.h"
#include "board.h"
#include "lvgl.h"

#include "fsl_gpio.h"
#include "fsl_port.h"
#include "fsl_smartdma.h"
#include "fsl_inputmux_connections.h"
#include "fsl_inputmux.h"


#include "wifi_lock_symbol.h"


#include "wlan.h"
#include "wifi.h"
#include "wm_net.h"
#include "dhcp-server.h"
#include "wifi_bt_config.h"

#include "fsl_common.h"
#include "wpl.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define I2C_RELEASE_SDA_PORT  PORT4
#define I2C_RELEASE_SCL_PORT  PORT4
#define I2C_RELEASE_SDA_GPIO  GPIO4
#define I2C_RELEASE_SDA_PIN   0U
#define I2C_RELEASE_SCL_GPIO  GPIO4
#define I2C_RELEASE_SCL_PIN   1U
#define I2C_RELEASE_BUS_COUNT 100U
static volatile bool s_lvgl_initialized = false;


enum wifi_lcd_event_reason
{
    WIFI_INIT,
	WIFI_INIT_FAIL,
	WIFI_INIT_DONE,
	WIFI_SCAN,
	WIFI_SCAN_START,
	WIFI_SCAN_FAIL,
	WIFI_SCAN_DONE,
	WIFI_BAD_PARAM,
	WIFI_NW_NOT_FOUND,
	WIFI_CONNECT,
	WIFI_CONNECT_FAIL,
	WIFI_AUTH_FAIL,
	WIFI_CONNECT_DONE
}WIFI_STATE=-1;

#if LV_USE_LOG
static void print_cb(const char *buf)
{
    PRINTF("\r%s\n", buf);
}
#endif

lv_obj_t * screen = NULL;
lv_obj_t * wifi_list = NULL;
#define MAX_NETWORKS 20
#define MAX_PASSWORD_LENGTH WPL_WIFI_PASSWORD_LENGTH

void prepare_network_information(void);
static void refresh_button_event_cb(lv_event_t * e);
static void create_refresh_button(void);
static void wifi_list_event_handler(lv_event_t * e);
static void wifi_credential_ui(const char *ssid);
static void lcd_buttun_event(lv_timer_t *timer);

static char password[MAX_PASSWORD_LENGTH] = {0};  // Buffer to store the actual password
static lv_obj_t *password_ta;  // Password text area
static lv_obj_t *show_password_cb;  // Show password checkbox

char wifi_buffer[MAX_NETWORKS][WPL_WIFI_SSID_LENGTH];  // Array to store Wi-Fi network names
int wifi_buffer_size = 0;  // Current number of networks in the buffer

static lv_obj_t * keyboard;
static lv_obj_t * password_textbox;
static lv_obj_t * scanning_label;
static lv_obj_t * connecting_label;
static lv_obj_t * spinner;
static bool scan_complete_flag = false;
static bool password_check_complete_flag = false;
static bool connection_successful = false;
static bool fatch_success = false;
static bool page_switch_success = false;
static lv_obj_t *refresh_btn;
char selected_ssid[128];
unsigned int selected_channel;
lv_obj_t *animation_screen;
static lv_style_t list_style;
static lv_style_t style_wifi_btn;
static lv_style_t form_style;
static lv_style_t large_text_style;
static lv_style_t ta_style;
static lv_style_t keyboard_style;
static lv_style_t key_style;
static lv_style_t large_text_style;
static lv_style_t cancel_list_style;
static lv_style_t refresh_scan_list_style;
static lv_style_t scan_list_style;

typedef struct {
    char scanned_ssid[WPL_WIFI_SSID_LENGTH];
    bool is_secured;  // Flag indicating if the network is secured
    unsigned int channel;
} wifi_network_t;

wifi_network_t network[MAX_NETWORKS];

typedef struct {
	uint8_t sta_mac_addrs[MLAN_MAC_ADDR_LENGTH];
	char ip_address[16];
	char netmask[16];
	char GW[16];
} sta_network_info_t;

sta_network_info_t station_info;

typedef struct {
	char ap_ssid[WPL_WIFI_SSID_LENGTH];
	char ap_bssid[IEEEtypes_ADDRESS_SIZE];
	char security [20];
	char mode[10];
	unsigned int chan;
} ap_network_info_t;

ap_network_info_t ap_info;


/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void LinkStatusChangeCallback(bool linkState);


/* Link lost callback */
static void LinkStatusChangeCallback(bool linkState)
{
    if (linkState == false)
    {
        PRINTF("-------- LINK LOST --------\r\n");
    }
    else
    {
        PRINTF("-------- LINK REESTABLISHED --------\r\n");
    }
}


static void printSeparator(void)
{
    PRINTF("========================================\r\n");
}

static struct wlan_network sta_network;

static const char *print_role(enum wlan_bss_role role)
{
    if (role == WLAN_BSS_ROLE_STA)
    {
        return "Infra";
    }
    else if (role == WLAN_BSS_ROLE_UAP)
    {
        return "uAP";
    }
    else if (role == WLAN_BSS_ROLE_ANY)
    {
        return "any";
    }
    else
    {
        return "unknown";
    }
}


static int __scan_cb(unsigned int count)
{
    struct wlan_scan_result res;
    unsigned int i,j;
    int err;
    uint8_t hidden_count = 0;

    if (count == 0U)
    {
        (void)PRINTF("no networks found\r\n");
        return 0;
    }

    (void)PRINTF("%d network%s found:\r\n", count, count == 1U ? "" : "s");
    wifi_buffer_size = (count < MAX_NETWORKS) ? count : MAX_NETWORKS;

    for (i = 0, j = 0; i < wifi_buffer_size; i++, j++)
    {
    	err = wlan_get_scan_result(i, &res);
        if (err != 0)
        {
            (void)PRINTF("Error: can't get scan res %d\r\n", i);
            continue;
        }

        print_mac(res.bssid);

        if (res.ssid[0] != '\0')
		{
			(void)PRINTF(" \"%s\" %s\r\n", res.ssid, print_role(res.role));
			strncpy(network[j].scanned_ssid, res.ssid, sizeof(network[j].scanned_ssid) - 1);
			network[j].channel = res.channel;
		}
        else
        {
            //(void)PRINTF(" (hidden) %s\r\n", print_role(res.role));
            hidden_count++;
            j--;
            continue;
        }
        (void)PRINTF("\tmode: ");
#ifdef CONFIG_11AC
#ifdef CONFIG_11AX
        if (res.dot11ax != 0U)
        {
            (void)PRINTF("802.11AX ");
        }
        else
#endif
            if (res.dot11ac != 0U)
        {
            (void)PRINTF("802.11AC ");
        }
        else
#endif
            if (res.dot11n != 0U)
        {
            (void)PRINTF("802.11N ");
        }
        else
        {
            (void)PRINTF("802.11BG ");
        }
        (void)PRINTF("\r\n");

        (void)PRINTF("\tchannel: %d\r\n", res.channel);
        (void)PRINTF("\trssi: -%d dBm\r\n", res.rssi);
        (void)PRINTF("\tsecurity: ");
        if (res.wep != 0U)
        {
            (void)PRINTF("WEP ");
        }
        if ((res.wpa != 0U) && (res.wpa2 != 0U))
        {
            (void)PRINTF("WPA/WPA2 Mixed ");
        }
        else if ((res.wpa2 != 0U) && (res.wpa3_sae != 0U))
        {
            (void)PRINTF("WPA2/WPA3 SAE Mixed ");
        }
        else
        {
            if (res.wpa != 0U)
            {
                (void)PRINTF("WPA ");
            }
            if (res.wpa2 != 0U)
            {
                (void)PRINTF("WPA2 ");
            }
            if (res.wpa2_sha256 != 0U)
            {
                (void)PRINTF("WPA2-SHA256");
            }
            if (res.wpa3_sae != 0U)
            {
                (void)PRINTF("WPA3-SAE ");
            }
#ifdef CONFIG_OWE
            if (res.owe != 0U)
            {
                (void)PRINTF("OWE Only");
            }
#endif
            if (res.wpa2_entp != 0U)
            {
                (void)PRINTF("WPA2 Enterprise ");
            }
            if (res.wpa2_entp_sha256 != 0U)
            {
                (void)PRINTF("WPA2-SHA256 Enterprise ");
            }
            if (res.wpa3_1x_sha256 != 0U)
            {
                (void)PRINTF("WPA3-SHA256 Enterprise ");
            }
            if (res.wpa3_1x_sha384 != 0U)
            {
                (void)PRINTF("WPA3-SHA384 Enterprise ");
            }
        }
#if defined(CONFIG_11R)
        if (res.ft_1x != 0U)
        {
            (void)PRINTF("with FT_802.1x");
        }
        if (res.ft_psk != 0U)
        {
            (void)PRINTF("with FT_PSK");
        }
        if (res.ft_sae != 0U)
        {
            (void)PRINTF("with FT_SAE");
        }
        if (res.ft_1x_sha384 != 0U)
        {
            (void)PRINTF("with FT_802.1x SHA384");
        }
#endif
        if (!((res.wep != 0U) || (res.wpa != 0U) || (res.wpa2 != 0U) || (res.wpa3_sae != 0U) || (res.wpa2_entp != 0U) ||
        		(res.wpa2_sha256 != 0U) ||
#ifdef CONFIG_OWE
				(res.owe != 0U) ||
#endif
				(res.wpa2_entp_sha256 != 0U) || (res.wpa3_1x_sha256 != 0U) || (res.wpa3_1x_sha384 != 0U)))
                {
                    (void)PRINTF("OPEN ");
                    network[j].is_secured = false;
                }
                else
                {
                    network[j].is_secured = true;
                }
        PRINTF("network[j].is_secured: %d\n", network[j].is_secured);

        (void)PRINTF("\r\n");

        (void)PRINTF("\tWMM: %s\r\n", (res.wmm != 0U) ? "YES" : "NO");

#ifdef CONFIG_11K
        if (res.neighbor_report_supported == true)
        {
            (void)PRINTF("\t802.11K: YES\r\n");
        }
#endif
#ifdef CONFIG_11V
        if (res.bss_transition_supported == true)
        {
            (void)PRINTF("\t802.11V: YES\r\n");
        }
#endif
        if ((res.ap_mfpc == true) && (res.ap_mfpr == true))
        {
            (void)PRINTF("\t802.11W: Capable, Required\r\n");
        }
        if ((res.ap_mfpc == true) && (res.ap_mfpr == false))
        {
            (void)PRINTF("\t802.11W: Capable\r\n");
        }
        if ((res.ap_mfpc == false) && (res.ap_mfpr == false))
        {
            (void)PRINTF("\t802.11W: NA\r\n");
        }
#ifdef CONFIG_WPA_SUPP_WPS
        if (res.wps)
        {
            if (res.wps_session == WPS_SESSION_PBC)
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "Push Button");
            else if (res.wps_session == WPS_SESSION_PIN)
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "PIN");
            else
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "Not active");
        }
        else
            (void)PRINTF("\tWPS: %s \r\n", "NO");
#endif
#ifdef CONFIG_OWE
        if (res.trans_ssid_len != 0U)
        {
            (void)PRINTF("\tOWE BSSID: ");
            print_mac(res.trans_bssid);
            (void)PRINTF("\r\n\tOWE SSID:");
            if (res.trans_ssid_len != 0U)
            {
                (void)PRINTF(" \"%s\"\r\n", res.trans_ssid);
            }
        }
#endif
        network[j].scanned_ssid[sizeof(wifi_buffer[j]) - 1] = '\0';  // Ensure null-termination
    }
    wifi_buffer_size -=  hidden_count;
    WIFI_STATE = WIFI_SCAN_DONE;
    return 0;
}


static void scan_wlan_network(void)
{
    if (wlan_scan(__scan_cb) != 0)
    {
        (void)PRINTF("Error: scan request failed\r\n");
        WIFI_STATE = WIFI_SCAN_FAIL;
        return;
    }
    else
    {
        (void)PRINTF("Scan scheduled...\r\n");
        WIFI_STATE = WIFI_SCAN_START;
    }
}


static void connect_wlan_network(void)
{
    int ret;
    struct wlan_ip_config addr;
    char ip[16];
    wpl_ret_t result;

    //check password

    /* Add Wifi network as known network */
	result = WPL_AddNetworkWithSecurityAndChannel(selected_ssid, password, selected_ssid, WPL_SECURITY_WILDCARD, selected_channel);
	if (result != WPLRET_SUCCESS)
	{
		PRINTF("[!] WPL_AddNetwork: Failed to add network, error:  %d\r\n", (uint32_t)result);

		switch (result)
		{
		case WPLRET_BAD_PARAM:
			WIFI_STATE = WIFI_BAD_PARAM;
			break;
		case WPLRET_FAIL:
			WIFI_STATE = WIFI_CONNECT_FAIL;
			break;
		default:
			WIFI_STATE = WIFI_CONNECT_FAIL;
			break;
		}
		return;
	}
	PRINTF("\r\nWPL_AddNetwork: Success\r\n");

	/* Join the network using label */
	PRINTF("Trying to join the network...\r\n");
	result = WPL_Join(selected_ssid);
	if (result != WPLRET_SUCCESS)
	{
		PRINTF("[!] WPL_Join: Failed to join network, error: %d\r\n", (uint32_t)result);
		if (WPL_RemoveNetwork(selected_ssid) != WPLRET_SUCCESS) {
			__BKPT(0);
		}
		switch (result)
		{
		case WPLRET_BAD_PARAM:
			WIFI_STATE = WIFI_BAD_PARAM;
			break;
		case WPLRET_FAIL:
			WIFI_STATE = WIFI_CONNECT_FAIL;
			break;
		case WPLRET_NOT_FOUND:
			WIFI_STATE = WIFI_NW_NOT_FOUND;
			break;
		case WPLRET_AUTH_FAILED:
			WIFI_STATE = WIFI_AUTH_FAIL;
			break;
		default:
			WIFI_STATE = WIFI_CONNECT_FAIL;
			break;
		}
		return;

	}
	PRINTF("WPL_Join: Success\r\n");
	WIFI_STATE = WIFI_CONNECT_DONE;

    ret = wlan_get_address(&addr);
    if (ret != WM_SUCCESS)
    {
        PRINTF("failed to get IP address\r\n");
        return;
    }

    net_inet_ntoa(addr.ipv4.address, ip);

    ret = wlan_get_current_network(&sta_network);
    if (ret != WM_SUCCESS)
    {
        PRINTF("Failed to get External AP network\r\n");
        return;
    }

    PRINTF("Connected to following BSS:\r\n");
    PRINTF("SSID = [%s]\r\n", sta_network.ssid);
    if (addr.ipv4.address != 0U)
    {
        PRINTF("IPv4 Address: [%s]\r\n", ip);
    }
#ifdef CONFIG_IPV6
    int i;
    for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        if (ip6_addr_isvalid(addr.ipv6[i].addr_state))
        {
            (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n",
                         ipv6_addr_type_to_desc((struct net_ipv6_config *)&addr.ipv6[i]),
                         inet6_ntoa(addr.ipv6[i].address), ipv6_addr_state_to_desc(addr.ipv6[i].addr_state));
        }
    }
    (void)PRINTF("\r\n");
#endif
    prepare_network_information();

}

void prepare_network_information()
{
	uint8_t sta_mac[MLAN_MAC_ADDR_LENGTH];
	uint8_t i;
	struct ip4_addr ip, gw, nm;

	if (wlan_get_mac_address(sta_mac))
	    {
	        (void)PRINTF("Error: unable to retrieve MAC address\r\n");
	    }
	    else
	    {
	    	for (i = 0; i < MLAN_MAC_ADDR_LENGTH ; i++)
	    		station_info.sta_mac_addrs[i] = sta_mac[i];
	    }

	strncpy(ap_info.ap_ssid, sta_network.ssid, sizeof (sta_network.ssid) - 1);
	for (i=0; i< IEEEtypes_ADDRESS_SIZE; i++)
		ap_info.ap_bssid[i] = sta_network.bssid[i];

	ap_info.chan = sta_network.channel;

	PRINTF("ssid %s\r\n chan %d\r\n", ap_info.ap_ssid, ap_info.chan );

	(void)PRINTF("BSSID %02X:%02X:%02X:%02X:%02X:%02X \r\n", ap_info.ap_bssid[0], ap_info.ap_bssid[1], ap_info.ap_bssid[2], ap_info.ap_bssid[3], ap_info.ap_bssid[4], ap_info.ap_bssid[5]);

	ip.addr   = sta_network.ip.ipv4.address;
	gw.addr   = sta_network.ip.ipv4.gw;
	nm.addr   = sta_network.ip.ipv4.netmask;

	strcpy (station_info.ip_address, inet_ntoa(ip));
	strcpy (station_info.GW, inet_ntoa(gw));
	strcpy (station_info.netmask, inet_ntoa(nm));

	PRINTF("ip %s\r\nGW %s\r\nnm %s\r\n",station_info.ip_address,station_info.GW, station_info.netmask);

	if (sta_network.dot11n != 0U)
		strcpy(ap_info.mode, "802.11N");
	else
		strcpy(ap_info.mode, "802.11BG");

	PRINTF("mode %s\n", ap_info.mode);

	//security
	switch (sta_network.security.type)
	{
		case WLAN_SECURITY_NONE:
		case WLAN_SECURITY_WEP_OPEN:
		strcpy(ap_info.security, "OPEN");
		break;
		case WLAN_SECURITY_WEP_SHARED:
		strcpy(ap_info.security, "WEP");
		break;
		case WLAN_SECURITY_WPA:
		strcpy(ap_info.security, "WPA");
		break;
		case WLAN_SECURITY_WPA2:
		strcpy(ap_info.security, "WPA2");
		break;
		case WLAN_SECURITY_WPA_WPA2_MIXED:
		strcpy(ap_info.security, "WPA/WPA2 Mixed");
		break;
		case WLAN_SECURITY_WPA2_FT:
		strcpy(ap_info.security, "FT");
		break;
		case WLAN_SECURITY_WPA3_SAE:
		strcpy(ap_info.security, "WPA3-SAE");
		break;
		case WLAN_SECURITY_WPA2_WPA3_SAE_MIXED:
		strcpy(ap_info.security, "WPA2/WPA3 SAE Mixed");
		break;
		case WLAN_SECURITY_OWE_ONLY:
		strcpy(ap_info.security, "OWE Only");
		break;
		case WLAN_SECURITY_WILDCARD:
		strcpy(ap_info.security, "Wildcard");
		break;
		default:
		strcpy(ap_info.security, "Unknown");
		break;
	}

	PRINTF("Security %s\r\n", ap_info.security);
}

void WifiTask (void *param)
{
    wpl_ret_t result;

    PRINTF("Initialize WLAN Driver\r\n");
    WIFI_STATE = WIFI_INIT;

    result = WPL_Init();
    if (result != WPLRET_SUCCESS)
    {
        PRINTF("[!] WPL_Init: Failed, error: %d\r\n", (uint32_t)result);
        WIFI_STATE = WIFI_INIT_FAIL;
        __BKPT(0);
        return;
    }
    PRINTF("[i] WPL_Init: Success\r\n");

    result = WPL_Start(LinkStatusChangeCallback);
    if (result != WPLRET_SUCCESS)
    {
        PRINTF("[!] WPL_Start: Failed, error: %d\r\n", (uint32_t)result);
        WIFI_STATE = WIFI_INIT_FAIL;
        __BKPT(0);
        return;
    }
    PRINTF("[i] WPL_Start: Success\r\n");
    WIFI_STATE = WIFI_INIT_DONE;

	while (1)
	{
		/* wait for interface up */
		os_thread_sleep(os_msec_to_ticks(10));
		switch (WIFI_STATE)
		{
			case WIFI_SCAN:
				scan_wlan_network();
				break;
			case WIFI_CONNECT:
				connect_wlan_network();
				break;
			default:
		}
	}
}

void setup_screen(void)
{
	lv_obj_clean(lv_scr_act());
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x000000), LV_PART_MAIN);  // Set background color to black


}

// Event handler for the password text area
static void password_text_area_event_handler(lv_event_t *e)
{

    lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t *textarea = lv_event_get_target(e);

    if (code == LV_EVENT_FOCUSED)
    {
    	lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);  // Hide keyboard initially
    	/* Attach the keyboard to the text area */
    	lv_keyboard_set_textarea(keyboard, textarea);
    }
    else if (code == LV_EVENT_DEFOCUSED)
    {
    	lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
    }


}

// Event handler for the "Show Password" checkbox
static void show_password_event_handler(lv_event_t *e)
{
    lv_obj_t *cb = lv_event_get_target(e);  // Get the checkbox
    bool is_checked = lv_obj_has_state(cb, LV_STATE_CHECKED);  // Check if it is selected

    if (is_checked)
    {
        // Show the actual password
        lv_textarea_set_text(password_ta, password);
    }
    else
    {
        // Mask the password with '*'
        lv_textarea_set_text(password_ta, "");  // Clear the text area
        for (size_t i = 0; i < strlen(password); i++)
        {
            lv_textarea_add_char(password_ta, '*');  // Add asterisks
        }
    }
}

// Event handler for keyboard input
static void keyboard_event_handler(lv_event_t * e)
{
    lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t *kb = lv_event_get_target(e);
    lv_obj_t * ta = lv_keyboard_get_textarea(kb);

    if (code == LV_EVENT_READY)
    {
        // "Done" button pressed, hide the keyboard
        lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
    }
    else if (code == LV_EVENT_CANCEL)
    {
        // "Cancel" button pressed, clear the text and hide the keyboard
        lv_textarea_set_text(ta, "");
        memset(password, 0, MAX_PASSWORD_LENGTH);  // Clear the buffer
        lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);
    }
    else if (code == LV_EVENT_VALUE_CHANGED)
    {
        // Synchronize the buffer with the textarea content
        const char *current_text = lv_textarea_get_text(ta);

        // Check if the current text length is within bounds
        size_t current_len = strlen(current_text);
        if (current_len < MAX_PASSWORD_LENGTH)
        {
            strncpy(password, current_text, current_len);
            password[current_len] = '\0';  // Ensure null-termination
        }

        // Ensure the buffer is null-terminated
        password[MAX_PASSWORD_LENGTH - 1] = '\0';
    }
}

void lcd_keyboard(void)
{

    // Create the keyboard (hidden initially)
    keyboard = lv_keyboard_create(lv_scr_act());
    lv_obj_set_size(keyboard, LV_HOR_RES, LV_VER_RES / 3);  // Resize keyboard to fit the screen
    lv_obj_align(keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);  // Hide keyboard initially

	if (keyboard_style.prop_cnt == 0)
	{
		lv_style_init(&keyboard_style);
	}

    // Set background color to black
    lv_style_set_bg_color(&keyboard_style, lv_color_hex(0x000000));

    // Apply the style to the keyboard background
    lv_obj_add_style(keyboard, &keyboard_style, LV_PART_MAIN);

    // Create a style for the text (key text)

	if (key_style.prop_cnt == 0)
	{
		lv_style_init(&key_style);
	}

    lv_style_set_bg_color(&key_style, lv_color_hex(0x000000));

    // Set the key text color to white
    lv_style_set_text_color(&key_style, lv_color_hex(0xFFFFFF));

    // Set border width and color for the keys (optional)
//    lv_style_set_border_width(&key_style, 1);
    lv_style_set_border_color(&key_style, lv_color_hex(0xFFFFFF));

    // Apply the style to the keyboard's keys
    lv_obj_add_style(keyboard, &key_style, LV_PART_ITEMS);

    lv_obj_add_event_cb(keyboard, keyboard_event_handler, LV_EVENT_VALUE_CHANGED, NULL);
}

// Function to toggle password visibility
static void password_toggle_event_cb(lv_event_t *e)
{
    lv_obj_t *checkbox = lv_event_get_target(e);
    lv_obj_t *passwd = (lv_obj_t *)lv_event_get_user_data(e);
    bool is_checked = lv_obj_has_state(checkbox, LV_STATE_CHECKED);

    if (is_checked) {
        lv_textarea_set_password_mode(passwd, false);  // Show password
    } else {
        lv_textarea_set_password_mode(passwd, true);   // Hide password
    }
}

void connected_wifi_info(void)
{
	setup_screen();
    // Create a title label
    lv_obj_t * label = lv_label_create(screen);
    lv_label_set_text(label, "Connection Details");
    lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
    lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);  // Position at the top center

    lv_obj_t *container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(container, LV_PCT(100), LV_PCT(70));

    lv_obj_set_style_border_width(container, 0, 0);  // Remove border
    lv_obj_set_style_bg_color(container, lv_color_hex(0x000000), 0);  // Dark background
    lv_obj_set_style_pad_all(container, 10, 0);  // Add padding
    lv_obj_align_to(container, label, LV_ALIGN_TOP_MID, 0, 45);

    if(large_text_style.prop_cnt == 0)
    {
    	lv_style_init(&large_text_style);
    }
    lv_style_set_text_color(&large_text_style, lv_color_white());
    lv_style_set_text_font(&large_text_style, &lv_font_montserrat_18);

    // Display SSID
    lv_obj_t *ssid_label = lv_label_create(container);
    lv_label_set_text_fmt(ssid_label, "SSID: %s", ap_info.ap_ssid);
    lv_obj_add_style(ssid_label, &large_text_style, 0);
    lv_obj_align(ssid_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *bssid_label = lv_label_create(container);
    lv_label_set_text_fmt(bssid_label, "BSSID: %02X:%02X:%02X:%02X:%02X:%02X ", ap_info.ap_bssid[0], ap_info.ap_bssid[1], ap_info.ap_bssid[2], ap_info.ap_bssid[3], ap_info.ap_bssid[4], ap_info.ap_bssid[5]);
    lv_obj_add_style(bssid_label, &large_text_style, 0);
    lv_obj_align_to(bssid_label, ssid_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *security_label = lv_label_create(container);
    lv_label_set_text_fmt(security_label, "Security: %s", ap_info.security);
    lv_obj_add_style(security_label, &large_text_style, 0);
    lv_obj_align_to(security_label, bssid_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *mode_label = lv_label_create(container);
    lv_label_set_text_fmt(mode_label, "Mode: %s", ap_info.mode);
    lv_obj_add_style(mode_label, &large_text_style, 0);
    lv_obj_align_to(mode_label, security_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *channel_label = lv_label_create(container);
    lv_label_set_text_fmt(channel_label, "Channel: %d", ap_info.chan);
    lv_obj_add_style(channel_label, &large_text_style, 0);
    lv_obj_align_to(channel_label, mode_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *network_label = lv_label_create(container);
    lv_label_set_text_fmt(network_label, "Network Information:");
    lv_obj_add_style(network_label, &large_text_style, 0);
    lv_obj_set_style_text_color(network_label, lv_color_hex(0x008B8B), LV_PART_MAIN);
    lv_obj_align_to(network_label, channel_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 30);

    lv_obj_t *ip_label = lv_label_create(container);
    lv_label_set_text_fmt(ip_label, "IP: %s", station_info.ip_address);
    lv_obj_add_style(ip_label, &large_text_style, 0);
    lv_obj_align_to(ip_label, network_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *netmask_label = lv_label_create(container);
    lv_label_set_text_fmt(netmask_label, "Netmask: %s", station_info.netmask);
    lv_obj_add_style(netmask_label, &large_text_style, 0);
    lv_obj_align_to(netmask_label, ip_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *gateway_label = lv_label_create(container);
    lv_label_set_text_fmt(gateway_label, "Gateway: %s", station_info.GW);
    lv_obj_add_style(gateway_label, &large_text_style, 0);
    lv_obj_align_to(gateway_label, netmask_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

    lv_obj_t *mac_label = lv_label_create(container);
    lv_label_set_text_fmt(mac_label, "MAC: %02X:%02X:%02X:%02X:%02X:%02X", station_info.sta_mac_addrs[0], station_info.sta_mac_addrs[1], station_info.sta_mac_addrs[2], station_info.sta_mac_addrs[3], station_info.sta_mac_addrs[4], station_info.sta_mac_addrs[5]);
    lv_obj_add_style(mac_label, &large_text_style, 0);
    lv_obj_align_to(mac_label, gateway_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);
}

static void wait_for_fatching_data(void)
{
	int fatch_count = 0;
	while (fatch_count < 1)
	{
		vTaskDelay(100);
		fatch_success = true;
		fatch_count++;
	}
}

static void fetching_handler(lv_timer_t *timer)
{
	wait_for_fatching_data();
	if (fatch_success)
	{
	    if (spinner != NULL)
	    {
	        lv_obj_del(spinner);
	        spinner = NULL;
	    }

	    connected_wifi_info();
	    lv_timer_del(timer);
	}
}

static void back_to_scan_data(void)
{
	WIFI_STATE = WIFI_SCAN_DONE;
	setup_screen();

	// Create a title label
	lv_obj_t * label = lv_label_create(screen);
	lv_label_set_text(label, "Wi-Fi Scan Result");
	lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);
	lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
	lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);

	create_refresh_button();

	wifi_list = lv_list_create(lv_scr_act());
	lv_obj_set_size(wifi_list, LV_PCT(100), LV_PCT(70));
	lv_obj_align_to(wifi_list, label, LV_ALIGN_TOP_MID, 0, 45);


	if (list_style.prop_cnt == 0)
	{
		lv_style_init(&list_style);
	}
	lv_style_set_bg_color(&list_style, lv_color_black());  // Set background to black
	lv_style_set_bg_opa(&list_style, LV_OPA_COVER);        // Ensure full opacity
	lv_style_set_border_width(&list_style, 0);             // Remove border of the list container
	lv_style_set_pad_row(&list_style, 10);

	lv_obj_add_style(wifi_list, &list_style, LV_PART_MAIN);

	if (style_wifi_btn.prop_cnt == 0)
	{
		lv_style_init(&style_wifi_btn);
	}
	lv_style_set_border_width(&style_wifi_btn, 0);        // Remove borders from list items
	lv_style_set_bg_color(&style_wifi_btn, lv_color_black());  // Make background black
	lv_style_set_bg_opa(&style_wifi_btn, LV_OPA_TRANSP);  // Transparent background for items
	lv_style_set_text_color(&style_wifi_btn, lv_color_white()); // Set text to white
	lv_style_set_pad_left(&style_wifi_btn, 10);
	lv_style_set_pad_right(&style_wifi_btn, 10);
	lv_style_set_text_font(&style_wifi_btn, &lv_font_montserrat_20);

	// Apply the style to list items
	lv_obj_add_style(wifi_list, &style_wifi_btn, LV_PART_ITEMS);

	for (int i = 0; i < wifi_buffer_size; i++)
	{
		char network_name[128] = {0};
		lv_obj_t * list_btn = lv_list_add_btn(wifi_list, LV_SYMBOL_WIFI, network[i].scanned_ssid);
		lv_obj_add_style(list_btn, &style_wifi_btn, 0);
		lv_obj_add_event_cb(list_btn, wifi_list_event_handler, LV_EVENT_CLICKED, NULL);
		if (network[i].is_secured)
		{
			lv_obj_t *lock_symbol = lv_img_create(list_btn);
			lv_img_set_src(lock_symbol, &lock);  // Set the lock image source
			lv_obj_align(lock_symbol, LV_ALIGN_OUT_RIGHT_MID, 5, 0);
		}
	}
}

static void wait_for_page_switch(void)
{
	int page_switch_wait_count = 0;
	while (page_switch_wait_count < 1)
	{
		vTaskDelay(100);
		page_switch_success = true;
		page_switch_wait_count++;
	}
}

static void back_to_scan_handler(lv_timer_t *timer)
{
	wait_for_page_switch();
	if (page_switch_success)
	{
	    if (spinner != NULL)
	    {
	        lv_obj_del(spinner);
	        spinner = NULL;
	    }

	    back_to_scan_data();
	    lv_timer_del(timer);
	}
}

static void back_to_credential_handler(lv_timer_t *timer)
{
	wait_for_page_switch();
	if (page_switch_success)
	{
	    if (spinner != NULL)
	    {
	        lv_obj_del(spinner);
	        spinner = NULL;
	    }
	    wifi_credential_ui(selected_ssid);
	    lv_timer_del(timer);
	}
}

static void connection_timer_cb(lv_timer_t *timer)
{
	if (WIFI_STATE == WIFI_CONNECT_DONE)
	{
        if (spinner != NULL)
        {
            lv_obj_del(spinner);
            spinner = NULL;
        }

        if (connecting_label != NULL)
        {
            lv_obj_del(connecting_label);
            connecting_label = NULL;
        }
		setup_screen();

		// Display success message

		char message[128];
		snprintf(message, sizeof(message),"%s", selected_ssid);

	    lv_obj_t *span_group = lv_spangroup_create(lv_scr_act());
	    lv_obj_set_width(span_group, lv_pct(70));  // Set the width of the span group to 70% of the screen
	    lv_obj_align(span_group, LV_ALIGN_CENTER, 0, 0);

	    // Normal text
	    lv_span_t *span1 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span1, "Successfully connected with ");
	    lv_style_set_text_color(&span1->style, lv_color_hex(0x008B8B));
	    lv_style_set_text_font(&span1->style, &lv_font_montserrat_20);
	    lv_obj_set_style_text_align(span_group, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);

	    // Highlighted word
	    lv_span_t *span2 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span2, message);
	    lv_style_set_text_color(&span2->style, lv_color_hex(0xFF8C00));
	    lv_style_set_text_font(&span2->style, &lv_font_montserrat_20);

	    // Remaining text
	    lv_span_t *span3 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span3, " network\n\n Fetching Network Information");
	    lv_style_set_text_color(&span3->style, lv_color_hex(0x008B8B));
	    lv_style_set_text_font(&span3->style, &lv_font_montserrat_20);

	    // Enable automatic wrapping
	    lv_spangroup_set_mode(span_group, LV_SPAN_MODE_BREAK);

		lv_timer_create(fetching_handler, 1500, NULL);

		spinner = lv_spinner_create(lv_scr_act(), 1000, 60);
		lv_obj_set_size(spinner, 50, 50);  // Set spinner size
	    lv_obj_set_style_arc_color(spinner, lv_color_hex(0x006400), LV_PART_INDICATOR);
	    lv_obj_set_style_arc_width(spinner, 2, LV_PART_INDICATOR);
	    lv_obj_set_style_arc_color(spinner, lv_color_hex(0x000000), LV_PART_MAIN);
	    lv_obj_align_to(spinner, span_group, LV_ALIGN_OUT_BOTTOM_MID, 0, 10);

		// Delete the timer after completion
		lv_timer_del(timer);
	}
	else if ((WIFI_STATE == WIFI_AUTH_FAIL) || (WIFI_STATE == WIFI_CONNECT_FAIL) || (WIFI_STATE == WIFI_NW_NOT_FOUND))
	{
        if (spinner != NULL)
        {
            lv_obj_del(spinner);
            spinner = NULL;
        }

        if (connecting_label != NULL)
        {
            lv_obj_del(connecting_label);
            connecting_label = NULL;
        }
		setup_screen();

		lv_obj_t *fail_label = lv_label_create(lv_scr_act());
		lv_obj_set_width(fail_label, 280);
		lv_label_set_long_mode(fail_label, LV_LABEL_LONG_WRAP);
		lv_obj_set_style_text_align(fail_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
		char message[128];
		if (WIFI_STATE == WIFI_AUTH_FAIL)
		{
			snprintf(message, sizeof(message),"Authentication fail !!!\n\nWrong password for %s network", selected_ssid);
		}
		else if (WIFI_STATE == WIFI_CONNECT_FAIL)
		{
			snprintf(message, sizeof(message),"Connection fail with %s network", selected_ssid);
		}
		else if (WIFI_STATE == WIFI_NW_NOT_FOUND)
		{
			snprintf(message, sizeof(message),"Connection fail !!!\n\nNo network found", selected_ssid);
		}
		lv_label_set_text(fail_label, message);
		lv_obj_set_style_text_color(fail_label, lv_color_hex(0xFF8C00), LV_PART_MAIN);
		lv_obj_set_style_text_font(fail_label, &lv_font_montserrat_22, LV_PART_MAIN);
		lv_obj_align(fail_label, LV_ALIGN_CENTER, 0, 0);

		lv_timer_create(back_to_scan_handler, 1500, NULL);
	}
}

static void cancel_button_event_cb(lv_event_t *e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED)
    {
		setup_screen();

		// Create a title label
		lv_obj_t * label = lv_label_create(screen);
		lv_label_set_text(label, "Wi-Fi Scan Result");
		lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);
		lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
		lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);  // Position at the top center

		create_refresh_button();

		wifi_list = lv_list_create(lv_scr_act());
		lv_obj_set_size(wifi_list, LV_PCT(100), LV_PCT(70));
		lv_obj_align_to(wifi_list, label, LV_ALIGN_TOP_MID, 0, 45);


		if (cancel_list_style.prop_cnt == 0)
		{
			lv_style_init(&cancel_list_style);
		}
		lv_style_set_bg_color(&cancel_list_style, lv_color_black());  // Set background to black
		lv_style_set_bg_opa(&cancel_list_style, LV_OPA_COVER);        // Ensure full opacity
		lv_style_set_border_width(&cancel_list_style, 0);             // Remove border of the list container
		lv_style_set_pad_row(&cancel_list_style, 10);

		lv_obj_add_style(wifi_list, &cancel_list_style, LV_PART_MAIN);

		if (style_wifi_btn.prop_cnt == 0)
		{
			lv_style_init(&style_wifi_btn);
		}
		lv_style_set_border_width(&style_wifi_btn, 0);        // Remove borders from list items
		lv_style_set_bg_color(&style_wifi_btn, lv_color_black());  // Make background black
		lv_style_set_bg_opa(&style_wifi_btn, LV_OPA_TRANSP);  // Transparent background for items
		lv_style_set_text_color(&style_wifi_btn, lv_color_white()); // Set text to white
		lv_style_set_pad_left(&style_wifi_btn, 10);
		lv_style_set_pad_right(&style_wifi_btn, 10);
		lv_style_set_text_font(&style_wifi_btn, &lv_font_montserrat_20);

		// Apply the style to list items
		lv_obj_add_style(wifi_list, &style_wifi_btn, LV_PART_ITEMS);

		for (int i = 0; i < wifi_buffer_size; i++)
		{
			char network_name[128] = {0};
			lv_obj_t * list_btn = lv_list_add_btn(wifi_list, LV_SYMBOL_WIFI, network[i].scanned_ssid);
			lv_obj_add_style(list_btn, &style_wifi_btn, 0);
			lv_obj_add_event_cb(list_btn, wifi_list_event_handler, LV_EVENT_CLICKED, NULL);
			if (network[i].is_secured)
			{
				lv_obj_t *lock_symbol = lv_img_create(list_btn);
				lv_img_set_src(lock_symbol, &lock);  // Set the lock image source
				lv_obj_align(lock_symbol, LV_ALIGN_OUT_RIGHT_MID, 5, 0);
			}
		}
    }
}

// Event callback for Connect button
static void connect_button_event_cb(lv_event_t *e)
{
	if ((strlen(password) >= WPL_WIFI_PASSWORD_MIN_LEN) && (strlen(password) <= MAX_PASSWORD_LENGTH))
	{
		PRINTF("Connecting to SSID with password: %s : %s\n", selected_ssid, password);
		char message[128];
		snprintf(message, sizeof(message), "%s", selected_ssid);
		setup_screen();

	    lv_obj_t *span_group = lv_spangroup_create(lv_scr_act());
	    lv_obj_set_width(span_group, lv_pct(70));
	    lv_obj_align(span_group, LV_ALIGN_CENTER, 0, 0);

	    // Normal text
	    lv_span_t *span1 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span1, "Attempting connection to ");
	    lv_style_set_text_color(&span1->style, lv_color_hex(0xFF8C00));
	    lv_style_set_text_font(&span1->style, &lv_font_montserrat_20);
	    lv_obj_set_style_text_align(span_group, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);

	    // Highlighted word
	    lv_span_t *span2 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span2, message);
	    lv_style_set_text_color(&span2->style, lv_color_hex(0x006400));
	    lv_style_set_text_font(&span2->style, &lv_font_montserrat_20);

	    // Remaining text
	    lv_span_t *span3 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span3, " network");
	    lv_style_set_text_color(&span3->style, lv_color_hex(0xFF8C00));
	    lv_style_set_text_font(&span3->style, &lv_font_montserrat_20);

	    // Enable automatic wrapping
	    lv_spangroup_set_mode(span_group, LV_SPAN_MODE_BREAK);

		spinner = lv_spinner_create(lv_scr_act(), 1000, 60);
		lv_obj_set_size(spinner, 50, 50);  // Set spinner size
		lv_obj_set_style_arc_color(spinner, lv_color_hex(0xAEC6CF), LV_PART_INDICATOR);
		lv_obj_set_style_arc_width(spinner, 2, LV_PART_INDICATOR);
		lv_obj_set_style_arc_color(spinner, lv_color_hex(0x000000), LV_PART_MAIN);
		lv_obj_align_to(spinner, span_group, LV_ALIGN_OUT_BOTTOM_MID, 0, 10);

		WIFI_STATE = WIFI_CONNECT;

		lv_timer_create(connection_timer_cb, 50, NULL);
	}
	else
	{
		setup_screen();
		lv_obj_t * bad_parameter_label = lv_label_create(lv_scr_act());
		lv_obj_set_width(bad_parameter_label, 280);
		lv_label_set_long_mode(bad_parameter_label, LV_LABEL_LONG_WRAP);
		lv_obj_set_style_text_align(bad_parameter_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
		char message[128];
		snprintf(message, sizeof(message), "Bad Parameter !!!\n\nPassword should be minimum %d characters and maximum %d characters", WPL_WIFI_PASSWORD_MIN_LEN, MAX_PASSWORD_LENGTH);
		lv_label_set_text(bad_parameter_label, message);
		lv_obj_set_style_text_color(bad_parameter_label, lv_color_hex(0xFF8C00), LV_PART_MAIN);  // White text
		lv_obj_set_style_text_font(bad_parameter_label, &lv_font_montserrat_20, LV_PART_MAIN);
		lv_obj_align(bad_parameter_label, LV_ALIGN_CENTER, 0, 0);
		lv_timer_create(back_to_credential_handler, 3000, NULL);
	}
}

// Event callback for the password text box (to show the keyboard)
static void password_focus_event_cb(lv_event_t *e)
{
	int event = lv_event_get_code(e);
    if (event == LV_EVENT_FOCUSED)
    {
    	 lv_obj_clear_flag(keyboard, LV_OBJ_FLAG_HIDDEN);;  // Show keyboard when the password field is focused
    }
    else if (event == LV_EVENT_DEFOCUSED)
    {
    	lv_obj_add_flag(keyboard, LV_OBJ_FLAG_HIDDEN);   // Hide keyboard when the password field loses focus
    }
}

static void wifi_credential_ui(const char *ssid)
{
	char ssid_buffer[32];
	strncpy(ssid_buffer, ssid, sizeof(ssid_buffer) - 1);
	ssid_buffer[sizeof(ssid_buffer) - 1] = '\0';  // Force null-termination

	snprintf(selected_ssid, sizeof(selected_ssid), ssid);

	setup_screen();
    // Create a title label
    lv_obj_t * label = lv_label_create(screen);
    lv_label_set_text(label, "Enter Wi-Fi Password");
    lv_obj_set_style_text_color(label, lv_color_hex(0x87CEEB), LV_PART_MAIN);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
    lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);  // Position at the top center

	lv_obj_t *form = lv_obj_create(screen);
	lv_obj_set_size(form, 450, 250);  // Form size
	lv_obj_align(form, LV_ALIGN_TOP_MID, 0, 60);  // Center, slightly upward
	lv_obj_set_style_bg_color(form, lv_color_black(), 0);
	lv_obj_set_style_radius(form, 5, 0);  // Rounded corners
	lv_obj_set_scrollbar_mode(form, LV_SCROLLBAR_MODE_AUTO);

	if (form_style.prop_cnt == 0)
	{
		lv_style_init(&form_style);
	}
	lv_style_set_border_width(&form_style, 2);  // Set border width (2 pixels)
	lv_style_set_border_color(&form_style, lv_color_hex(0x000000));
	lv_obj_add_style(form, &form_style, LV_PART_MAIN);

	if (large_text_style.prop_cnt == 0)
	{
		lv_style_init(&large_text_style);
	}

    lv_style_set_text_color(&large_text_style, lv_color_white());
    lv_style_set_text_font(&large_text_style, &lv_font_montserrat_18);

	// Password Label and Text Area
	lv_obj_t *password_label = lv_label_create(form);
	lv_label_set_text(password_label, ssid_buffer);
	lv_obj_add_style(password_label, &large_text_style, 0);
	lv_obj_align(password_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

	lv_obj_t *password_ta = lv_textarea_create(form);
	lv_textarea_set_placeholder_text(password_ta, "Enter Password");
	lv_textarea_set_one_line(password_ta, true);
	lv_textarea_set_password_mode(password_ta, true);  // Mask input
	lv_obj_set_width(password_ta, 200);
	lv_obj_align_to(password_ta, password_label, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 10);

	if (ta_style.prop_cnt == 0)
	{
		lv_style_init(&ta_style);
	}
	lv_style_set_bg_color(&ta_style, lv_color_hex(0x000000));  // Black background
	lv_style_set_text_color(&ta_style, lv_color_hex(0xFFFFFF));
	lv_style_set_border_width(&ta_style, 2);

	// Apply the style to the text area
	lv_obj_add_style(password_ta, &ta_style, LV_PART_MAIN);

	lv_obj_add_event_cb(password_ta, password_text_area_event_handler, LV_EVENT_ALL, NULL);

	// Show Password Checkbox
	lv_obj_t *show_password_cb = lv_checkbox_create(form);
	lv_checkbox_set_text(show_password_cb, "Show Password");
	lv_obj_add_style(show_password_cb, &large_text_style, 0);
	lv_obj_align_to(show_password_cb, password_ta, LV_ALIGN_OUT_BOTTOM_LEFT, 0, 35);
	lv_obj_add_event_cb(show_password_cb, password_toggle_event_cb, LV_EVENT_VALUE_CHANGED, password_ta);

	// Connect Button
	lv_obj_t *connect_btn = lv_btn_create(form);
	lv_obj_set_size(connect_btn, 130, 50);  // Button size
	lv_obj_align_to(connect_btn, show_password_cb, LV_ALIGN_OUT_BOTTOM_MID, 200, 20);
	lv_obj_set_style_bg_color(connect_btn, lv_color_hex(0xC3E701), LV_PART_MAIN);  // Green color
	lv_obj_set_style_bg_opa(connect_btn, LV_OPA_COVER, LV_PART_MAIN);

	lv_obj_t *connect_label = lv_label_create(connect_btn);
	lv_label_set_text(connect_label, "Connect");
    lv_obj_set_style_text_color(connect_label, lv_color_hex(0xFFFFFF), LV_PART_MAIN);  // White text
    lv_obj_set_style_text_font(connect_label, &lv_font_montserrat_20, LV_PART_MAIN);
	lv_obj_center(connect_label);

	// Pass both SSID and Password text areas to the event handler
	lv_obj_add_event_cb(connect_btn, connect_button_event_cb, LV_EVENT_CLICKED, NULL);

	lv_obj_t * cancel_btn = lv_btn_create(form);
	lv_obj_set_size(cancel_btn, 130, 50);
	lv_obj_align_to(cancel_btn,show_password_cb, LV_ALIGN_OUT_BOTTOM_MID, 30, 20);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_hex(0xFFA500), LV_PART_MAIN);  // Orange color
    lv_obj_set_style_bg_opa(cancel_btn, LV_OPA_COVER, LV_PART_MAIN);

    lv_obj_t *cancel_label = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_label, "Cancel");

    // Set label text color to white
    lv_obj_set_style_text_color(cancel_label, lv_color_hex(0xFFFFFF), LV_PART_MAIN);  // White text
    lv_obj_set_style_text_font(cancel_label, &lv_font_montserrat_20, LV_PART_MAIN);
    lv_obj_center(cancel_label);  // Center the label within the button

    lv_obj_add_event_cb(cancel_btn, cancel_button_event_cb, LV_EVENT_CLICKED, NULL);

    lcd_keyboard();

    // Event handler for password text box (to show the keyboard)
    lv_obj_add_event_cb(password_ta, password_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(password_ta, password_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

}

// Event handler for the button
static void wifi_list_event_handler(lv_event_t * e)
{
	int i = 0;
	lv_obj_t * btn = lv_event_get_target(e);
	const char *selected_network = lv_list_get_btn_text(wifi_list,btn);
    for (i = 0;  i< wifi_buffer_size; i++)
    {
    	if (!strcmp(network[i].scanned_ssid, selected_network))
	{
		selected_channel = network[i].channel;
    		break;
	}
    }


    if(network[i].is_secured)
    {
    	wifi_credential_ui(selected_network);
    }
    else
    {
        snprintf(selected_ssid, sizeof(selected_ssid), selected_network);
        char message[128];
    	snprintf(message, sizeof(message), "%s", selected_ssid);
        setup_screen();

	    lv_obj_t *span_group = lv_spangroup_create(lv_scr_act());
	    lv_obj_set_width(span_group, lv_pct(70));
	    lv_obj_align(span_group, LV_ALIGN_CENTER, 0, 0);

	    // Normal text
	    lv_span_t *span1 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span1, "Attempting connection to ");
	    lv_style_set_text_color(&span1->style, lv_color_hex(0xFF8C00));
	    lv_style_set_text_font(&span1->style, &lv_font_montserrat_20);
	    lv_obj_set_style_text_align(span_group, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);

	    // Highlighted word
	    lv_span_t *span2 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span2, message);
	    lv_style_set_text_color(&span2->style, lv_color_hex(0x006400));
	    lv_style_set_text_font(&span2->style, &lv_font_montserrat_20);

	    // Remaining text
	    lv_span_t *span3 = lv_spangroup_new_span(span_group);
	    lv_span_set_text(span3, " network");
	    lv_style_set_text_color(&span3->style, lv_color_hex(0xFF8C00));
	    lv_style_set_text_font(&span3->style, &lv_font_montserrat_20);

	    // Enable automatic wrapping
	    lv_spangroup_set_mode(span_group, LV_SPAN_MODE_BREAK);

    	spinner = lv_spinner_create(lv_scr_act(), 1000, 60);
    	lv_obj_set_size(spinner, 50, 50);  // Set spinner size
        lv_obj_set_style_arc_color(spinner, lv_color_hex(0xAEC6CF), LV_PART_INDICATOR);
        lv_obj_set_style_arc_width(spinner, 2, LV_PART_INDICATOR);
        lv_obj_set_style_arc_color(spinner, lv_color_hex(0x000000), LV_PART_MAIN);
    	lv_obj_align_to(spinner, connecting_label, LV_ALIGN_OUT_BOTTOM_MID, 0, 10);


    	lv_timer_create(connection_timer_cb, 500, NULL);
    	WIFI_STATE = WIFI_CONNECT;
    }
}

static void create_refresh_button()
{
	refresh_btn = lv_btn_create(lv_scr_act());
	lv_obj_set_size(refresh_btn, 60, 30);  // Button size
	lv_obj_align(refresh_btn, LV_ALIGN_TOP_RIGHT, -10, 15);

	lv_obj_set_style_text_font(refresh_btn, &lv_font_montserrat_14, LV_PART_MAIN);
	lv_obj_set_style_bg_color(refresh_btn, lv_color_hex(0x000000), LV_PART_MAIN);
	lv_obj_set_style_text_color(refresh_btn, lv_color_hex(0x00FF00), LV_PART_MAIN);

	lv_obj_t *refresh_label = lv_label_create(refresh_btn);
	lv_label_set_text(refresh_label, "Refresh");
	lv_obj_center(refresh_label);

	// Pass both SSID and Password text areas to the event handler
	lv_obj_add_event_cb(refresh_btn, refresh_button_event_cb, LV_EVENT_CLICKED, NULL);
}

static void refresh_scan_handler(lv_timer_t *timer)
{
	if (WIFI_STATE == WIFI_SCAN_DONE)
	{
		if (spinner != NULL)
		{
			lv_obj_del(spinner);
			spinner = NULL;
		}
        setup_screen();

        // Create a title label
        lv_obj_t * label = lv_label_create(screen);
        lv_label_set_text(label, "Wi-Fi Scan Result");
        lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);  // Set text color to white
        lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);  // Position at the top center

        create_refresh_button();

		wifi_list = lv_list_create(lv_scr_act());
		lv_obj_set_size(wifi_list, LV_PCT(100), LV_PCT(70));
		lv_obj_align_to(wifi_list, label, LV_ALIGN_TOP_MID, 0, 45);

		if (refresh_scan_list_style.prop_cnt == 0)
		{
			lv_style_init(&refresh_scan_list_style);
		}
		lv_style_set_bg_color(&refresh_scan_list_style, lv_color_black());  // Set background to black
		lv_style_set_bg_opa(&refresh_scan_list_style, LV_OPA_COVER);        // Ensure full opacity
		lv_style_set_border_width(&refresh_scan_list_style, 0);             // Remove border of the list container
		lv_style_set_pad_row(&refresh_scan_list_style, 10);

		lv_obj_add_style(wifi_list, &refresh_scan_list_style, LV_PART_MAIN);


		if (style_wifi_btn.prop_cnt == 0)
		{
			lv_style_init(&style_wifi_btn);
		}
		lv_style_set_border_width(&style_wifi_btn, 0);        // Remove borders from list items
		lv_style_set_bg_color(&style_wifi_btn, lv_color_black());  // Make background black
		lv_style_set_bg_opa(&style_wifi_btn, LV_OPA_TRANSP);  // Transparent background for items
		lv_style_set_text_color(&style_wifi_btn, lv_color_white()); // Set text to white
		lv_style_set_pad_left(&style_wifi_btn, 10);           // Optional: Add left padding
		lv_style_set_pad_right(&style_wifi_btn, 10);          // Optional: Add right padding
		lv_style_set_text_font(&style_wifi_btn, &lv_font_montserrat_20);

		// Apply the style to list items
		lv_obj_add_style(wifi_list, &style_wifi_btn, LV_PART_ITEMS);

		for (int i = 0; i < wifi_buffer_size; i++)
		{
			char network_name[128] = {0};
			lv_obj_t * list_btn = lv_list_add_btn(wifi_list, LV_SYMBOL_WIFI, network[i].scanned_ssid);
			lv_obj_add_style(list_btn, &style_wifi_btn, 0);
			lv_obj_add_event_cb(list_btn, wifi_list_event_handler, LV_EVENT_CLICKED, NULL);
			if (network[i].is_secured)
			{
				lv_obj_t *lock_symbol = lv_img_create(list_btn);
				lv_img_set_src(lock_symbol, &lock);  // Set the lock image source
				lv_obj_align(lock_symbol, LV_ALIGN_OUT_RIGHT_MID, 5, 0);
			}
		}
		lv_timer_del(timer);
	}
}

static void refresh_button_event_cb(lv_event_t * e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED)
    {
    	WIFI_STATE = WIFI_SCAN;
        lv_obj_del(refresh_btn);

        // Create a green spinner in place of the button
        spinner = lv_spinner_create(lv_scr_act(), 1000, 90);  // 1000ms, 90 arc size
        lv_obj_set_size(spinner, 30, 30);  // Set spinner size
        lv_obj_align(spinner, LV_ALIGN_TOP_RIGHT, -20, 20);  // Align spinner where the button was
        lv_obj_set_style_arc_color(spinner, lv_color_hex(0x00FF00), LV_PART_INDICATOR);
        lv_obj_set_style_arc_width(spinner, 2, LV_PART_INDICATOR);
        lv_obj_set_style_arc_color(spinner, lv_color_hex(0x000000), LV_PART_MAIN);
    	lv_timer_create(refresh_scan_handler, 500, NULL);
    }
}

static void wifi_scan_handler(lv_timer_t *timer)
{
    if (WIFI_STATE == WIFI_SCAN_DONE)
    {
		if (spinner != NULL)
		{
			lv_obj_del(spinner);
			spinner = NULL;
		}
        if (scanning_label != NULL)
        {
            lv_obj_del(scanning_label);
            scanning_label = NULL;
        }

        setup_screen();

        // Create a title label
        lv_obj_t * label = lv_label_create(screen);
        lv_label_set_text(label, "Wi-Fi Scan Result");
        lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);
        lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);

        create_refresh_button();

        wifi_list = lv_list_create(lv_scr_act());
        lv_obj_set_size(wifi_list, LV_PCT(100), LV_PCT(70));
        lv_obj_align_to(wifi_list, label, LV_ALIGN_TOP_MID, 0, 45);

		if (scan_list_style.prop_cnt == 0)
		{
			lv_style_init(&scan_list_style);
		}
        lv_style_set_bg_color(&scan_list_style, lv_color_black());  // Set background to black
        lv_style_set_bg_opa(&scan_list_style, LV_OPA_COVER);
        lv_style_set_border_width(&scan_list_style, 0);             // Remove border of the list container
        lv_style_set_pad_row(&scan_list_style, 10);

        lv_obj_add_style(wifi_list, &scan_list_style, LV_PART_MAIN);

		if (style_wifi_btn.prop_cnt == 0)
		{
			lv_style_init(&style_wifi_btn);
		}
        lv_style_set_border_width(&style_wifi_btn, 0);        // Remove borders from list items
        lv_style_set_bg_color(&style_wifi_btn, lv_color_black());  // Make background black
        lv_style_set_bg_opa(&style_wifi_btn, LV_OPA_TRANSP);  // Transparent background for items
        lv_style_set_text_color(&style_wifi_btn, lv_color_white());
        lv_style_set_pad_left(&style_wifi_btn, 10);
        lv_style_set_pad_right(&style_wifi_btn, 10);
        lv_style_set_text_font(&style_wifi_btn, &lv_font_montserrat_20);

        // Apply the style to list items
        lv_obj_add_style(wifi_list, &style_wifi_btn, LV_PART_ITEMS);

        for (int i = 0; i < wifi_buffer_size; i++)
        {
        	char network_name[128] = {0};
            lv_obj_t * list_btn = lv_list_add_btn(wifi_list, LV_SYMBOL_WIFI, network[i].scanned_ssid);
            lv_obj_add_style(list_btn, &style_wifi_btn, 0);
            lv_obj_add_event_cb(list_btn, wifi_list_event_handler, LV_EVENT_CLICKED, NULL);
        	if (network[i].is_secured)
        	{
                lv_obj_t *lock_symbol = lv_img_create(list_btn);
                lv_img_set_src(lock_symbol, &lock);  // Set the lock image source
                lv_obj_align(lock_symbol, LV_ALIGN_OUT_RIGHT_MID, 5, 0);
        	}
        }

        lv_timer_del(timer);
    }
    else if (WIFI_STATE == WIFI_SCAN_FAIL)
    {
		if (spinner != NULL)
		{
			lv_obj_del(spinner);
			spinner = NULL;
		}
        if (scanning_label != NULL)
        {
            lv_obj_del(scanning_label);
            scanning_label = NULL;
        }

        setup_screen();
        lv_obj_t * label = lv_label_create(screen);
        lv_label_set_text(label, "Wi-Fi Scan Request Fail...\n\nPlease try again.");
        lv_obj_set_style_text_color(label, lv_color_hex(0xFF8C00), LV_PART_MAIN);  // Set text color to white
        lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
        lv_obj_align(label, LV_ALIGN_CENTER, 0, 0);  // Position at the top center
        WIFI_STATE = WIFI_INIT_DONE;

        lv_timer_create(lcd_buttun_event, 5000, NULL);

    }
}

static void btn_event_handler(lv_event_t * e)
{
    if (lv_event_get_code(e) == LV_EVENT_CLICKED)
    {

        WIFI_STATE = WIFI_SCAN;
        setup_screen();
        scanning_label = lv_label_create(lv_scr_act());
		lv_label_set_text(scanning_label, "Scanning");
		lv_obj_set_style_text_color(scanning_label, lv_color_hex(0x87CEEB), LV_PART_MAIN);
		lv_obj_set_style_text_font(scanning_label, &lv_font_montserrat_24, LV_PART_MAIN);
		lv_obj_align(scanning_label, LV_ALIGN_CENTER, 0, -20);
		lv_timer_create(wifi_scan_handler, 500, NULL);

		spinner = lv_spinner_create(lv_scr_act(), 1000, 60);
		lv_obj_set_size(spinner, 50, 50);  // Set spinner size
		lv_obj_align_to(spinner, scanning_label, LV_ALIGN_OUT_BOTTOM_MID, 0, 10);
		lv_obj_set_style_arc_color(spinner, lv_color_hex(0x00FF00), LV_PART_INDICATOR);
		lv_obj_set_style_arc_width(spinner, 2, LV_PART_INDICATOR);
		lv_obj_set_style_arc_color(spinner, lv_color_hex(0x000000), LV_PART_MAIN);
    }
}

static void lcd_buttun_event(lv_timer_t *timer)
{
	screen = lv_scr_act();
	if(WIFI_STATE == WIFI_INIT_DONE)
	{
		setup_screen();

		// Create a title label
		lv_obj_t * label = lv_label_create(screen);
		lv_label_set_text(label, "Connect to Wi-Fi");
		lv_obj_set_style_text_color(label, lv_color_hex(0x00FF00), LV_PART_MAIN);
		lv_obj_set_style_text_font(label, &lv_font_montserrat_22, LV_PART_MAIN);  // Set font size
		lv_obj_align(label, LV_ALIGN_TOP_MID, 0, 20);  // Position at the top center

		// Create a button
		lv_obj_t * btn = lv_btn_create(screen);
		lv_obj_set_size(btn, 250, 70);  // Set button size
		lv_obj_align(btn, LV_ALIGN_CENTER, 0, 0);  // Center the button
		lv_obj_add_event_cb(btn, btn_event_handler, LV_EVENT_CLICKED, NULL);  // Attach event handler

		// Create a label for the button
		lv_obj_t * btn_label = lv_label_create(btn);
		lv_label_set_text(btn_label, "Scan Wi-Fi Networks");
		lv_obj_set_style_text_color(btn_label, lv_color_hex(0xFFFF00), LV_PART_MAIN);  // Set text color to white
		lv_obj_set_style_text_font(btn_label, &lv_font_montserrat_20, LV_PART_MAIN);  // Set font size
		lv_obj_align(btn_label, LV_ALIGN_CENTER, 0, 0);  // Position at the center

		lv_timer_del(timer);
	}
	else if (WIFI_STATE == WIFI_INIT_FAIL)
	{
		setup_screen();
		lv_obj_t * wifi_init_fail_label = lv_label_create(lv_scr_act());
		lv_obj_set_width(wifi_init_fail_label, 280);
		lv_label_set_long_mode(wifi_init_fail_label, LV_LABEL_LONG_WRAP);
		lv_obj_set_style_text_align(wifi_init_fail_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
		lv_label_set_text(wifi_init_fail_label, "Wi-Fi Init Fail...\n\nCheck Module Connection, Jumper Settings or Reset the Board");
		lv_obj_set_style_text_color(wifi_init_fail_label, lv_color_hex(0xFF8C00), LV_PART_MAIN);  // White text
		lv_obj_set_style_text_font(wifi_init_fail_label, &lv_font_montserrat_20, LV_PART_MAIN);
		lv_obj_align(wifi_init_fail_label, LV_ALIGN_CENTER, 0, 0);
		lv_timer_del(timer);
	}
}

static void animation_end_cb(lv_anim_t *anim)
{
	lv_timer_create(lcd_buttun_event, 3000, NULL);
}

static void create_animation_screen(void)
{
    // Create the first screen (splash screen)
    animation_screen = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(animation_screen, lv_color_black(), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(animation_screen, LV_OPA_COVER, LV_PART_MAIN);


    lv_obj_t *label = lv_label_create(animation_screen);
    lv_label_set_text(label, "Wi-Fi Connect using LCD Interface");
    lv_obj_set_style_text_color(label, lv_color_hex(0x00FF00), LV_PART_MAIN);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_24, LV_PART_MAIN);
    lv_obj_set_style_text_opa(label, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_text_letter_space(label, 1, LV_PART_MAIN);
    lv_obj_set_style_text_decor(label, LV_TEXT_DECOR_NONE, LV_PART_MAIN);

    lv_obj_align(label, LV_ALIGN_CENTER, 0, 0);

    lv_anim_t anim;
    lv_anim_init(&anim);
    lv_anim_set_var(&anim, label);
    lv_anim_set_values(&anim, LV_VER_RES, LV_ALIGN_CENTER);  // Start off-screen, slide to center
    lv_anim_set_time(&anim, 3000);
    lv_anim_set_path_cb(&anim, lv_anim_path_ease_in_out);  // Easing function for smooth effect
    lv_anim_set_exec_cb(&anim, (lv_anim_exec_xcb_t)lv_obj_set_y);  // Animate Y position
    lv_anim_set_ready_cb(&anim, animation_end_cb);  // Callback to load the next screen
    lv_anim_start(&anim);  // Start the animation

    // Load the animation screen
    lv_scr_load(animation_screen);
}

static void AppTask(void *param)
{

#if LV_USE_LOG
    lv_log_register_print_cb(print_cb);
#endif

    lv_port_pre_init();
    lv_init();
    lv_port_disp_init();
    lv_port_indev_init();

    s_lvgl_initialized = true;

    create_animation_screen();

    vTaskDelay(5);


    for (;;)
    {
        lv_task_handler();
        vTaskDelay(5);
    }
}

/*******************************************************************************
 * Code
 ******************************************************************************/
void BOARD_I2C_ReleaseBus(void);

static void BOARD_InitSmartDMA(void)
{
    RESET_ClearPeripheralReset(kMUX_RST_SHIFT_RSTn);

    INPUTMUX_Init(INPUTMUX0);
    INPUTMUX_AttachSignal(INPUTMUX0, 0, kINPUTMUX_FlexioToSmartDma);

    /* Turnoff clock to inputmux to save power. Clock is only needed to make changes */
    INPUTMUX_Deinit(INPUTMUX0);

    SMARTDMA_InitWithoutFirmware();

    NVIC_EnableIRQ(SMARTDMA_IRQn);
    NVIC_SetPriority(SMARTDMA_IRQn, 3);
}


static void i2c_release_bus_delay(void)
{
    SDK_DelayAtLeastUs(100U, SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY);
}

void BOARD_I2C_ReleaseBus(void)
{
    uint8_t i = 0;
    gpio_pin_config_t pin_config;
    port_pin_config_t i2c_pin_config = {0};

    /* Config pin mux as gpio */
    i2c_pin_config.pullSelect = kPORT_PullUp;
    i2c_pin_config.mux        = kPORT_MuxAsGpio;

    pin_config.pinDirection = kGPIO_DigitalOutput;
    pin_config.outputLogic  = 1U;
    CLOCK_EnableClock(kCLOCK_Port4);
    PORT_SetPinConfig(I2C_RELEASE_SCL_PORT, I2C_RELEASE_SCL_PIN, &i2c_pin_config);
    PORT_SetPinConfig(I2C_RELEASE_SCL_PORT, I2C_RELEASE_SDA_PIN, &i2c_pin_config);

    GPIO_PinInit(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, &pin_config);
    GPIO_PinInit(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, &pin_config);

    /* Drive SDA low first to simulate a start */
    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 0U);
    i2c_release_bus_delay();

    /* Send 9 pulses on SCL and keep SDA high */
    for (i = 0; i < 9; i++)
    {
        GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 0U);
        i2c_release_bus_delay();

        GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 1U);
        i2c_release_bus_delay();

        GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 1U);
        i2c_release_bus_delay();
        i2c_release_bus_delay();
    }

    /* Send stop */
    GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 0U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 0U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 1U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 1U);
    i2c_release_bus_delay();
}
/*!
 * @brief Main function
 */
int main(void)
{
    BaseType_t stat;

    /* Init board hardware. */
    /* attach FRO 12M to FLEXCOMM4 (debug console) */
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom4Clk, 1u);
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    /* attach FRO 12M to FLEXCOMM2 */
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom2Clk, 1u);
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM2);

    CLOCK_SetClkDiv(kCLOCK_DivFlexioClk, 1u);
    CLOCK_AttachClk(kPLL0_to_FLEXIO);

    /* attach FRO HF to USDHC */
    CLOCK_SetClkDiv(kCLOCK_DivUSdhcClk, 1u);
    CLOCK_AttachClk(kFRO_HF_to_USDHC);

    BOARD_InitBootClocks();
    BOARD_I2C_ReleaseBus();
    BOARD_InitBootPins();
    BOARD_InitDebugConsole();
    
    /* Init smartdma. */
    BOARD_InitSmartDMA();

    stat = xTaskCreate(AppTask, "lvgl", configMINIMAL_STACK_SIZE + 5000, NULL, tskIDLE_PRIORITY + 2, NULL);

    if (pdPASS != stat)
    {
        PRINTF("Failed to create lvgl task");
        while (1)
            ;
    }

    stat = xTaskCreate(WifiTask, "wifi", configMINIMAL_STACK_SIZE + 800, NULL, tskIDLE_PRIORITY + 2, NULL);

    if (pdPASS != stat)
    {
        PRINTF("Failed to create lvgl task");
        while (1)
            ;
    }

    vTaskStartScheduler();

    for (;;)
    {
    } /* should never get here */
}

/*!
 * @brief Malloc failed hook.
 */
void vApplicationMallocFailedHook(void)
{
    PRINTF("Malloc failed. Increase the heap size.");

    for (;;)
        ;
}

/*!
 * @brief FreeRTOS tick hook.
 */
void vApplicationTickHook(void)
{
    if (s_lvgl_initialized)
    {
        lv_tick_inc(1);
    }
}

/*!
 * @brief Stack overflow hook.
 */
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)pcTaskName;
    (void)xTask;

    for (;;)
        ;
}

