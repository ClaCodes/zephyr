/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief New experimental USB device stack APIs and structures
 *
 * This file contains the USB device stack APIs and structures.
 */

#ifndef ZEPHYR_INCLUDE_USBD_H_
#define ZEPHYR_INCLUDE_USBD_H_

#include <zephyr/device.h>
#include <zephyr/usb/bos.h>
#include <zephyr/usb/usb_ch9.h>
#include <zephyr/usb/usbd_msg.h>
#include <zephyr/drivers/usb/udc_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/slist.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/iterable_sections.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New USB device stack core API
 * @defgroup usbd_api USB device core API
 * @ingroup usb
 * @since 3.3
 * @version 0.1.0
 * @{
 */

/* 1 if USB device stack is compiled with High-Speed support */
#define USBD_SUPPORTS_HIGH_SPEED IS_EQ(CONFIG_USBD_MAX_SPEED, 1)

/* Maximum bulk max packet size the stack supports */
#define USBD_MAX_BULK_MPS COND_CODE_1(USBD_SUPPORTS_HIGH_SPEED, (512), (64))

/*
 * The length of the string descriptor (bLength) is calculated from the
 * size of the two octets bLength and bDescriptorType plus the
 * length of the UTF16LE string:
 *
 *   bLength = 2 + bString_length
 *   bLength = 2 + sizeof(initializer_string) * 2 - 2
 *   bLength = sizeof(initializer_string) * 2
 * Use this macro to determine the bLength of the string descriptor.
 */
#define USB_STRING_DESCRIPTOR_LENGTH(s)	(sizeof(s) * 2)

struct usbd_context;

/** Used internally to keep descriptors in order
 * @cond INTERNAL_HIDDEN
 */
enum usbd_str_desc_utype {
	USBD_DUT_STRING_LANG,
	USBD_DUT_STRING_MANUFACTURER,
	USBD_DUT_STRING_PRODUCT,
	USBD_DUT_STRING_SERIAL_NUMBER,
	USBD_DUT_STRING_CONFIG,
	USBD_DUT_STRING_INTERFACE,
};

enum usbd_bos_desc_utype {
	USBD_DUT_BOS_NONE,
	USBD_DUT_BOS_VREQ,
};
/** @endcond */

/**
 * USBD string descriptor data
 */
struct usbd_str_desc_data {
	/** Descriptor index, required for string descriptors */
	uint8_t idx;
	/** Descriptor usage type (not bDescriptorType) */
	enum usbd_str_desc_utype utype : 8;
	/** The string descriptor is in ASCII7 format */
	unsigned int ascii7 : 1;
	/** Device stack obtains SerialNumber using the HWINFO API */
	unsigned int use_hwinfo : 1;
};

/**
 * USBD vendor request node
 *
 * Vendor request node is identified by the vendor code and is used to register
 * callbacks to handle the vendor request with the receiving device.
 * When the device stack receives a request with type Vendor and recipient
 * Device, and bRequest value equal to the vendor request code, it will call
 * the vendor callbacks depending on the direction of the request.
 *
 * Example callback code fragment:
 *
 * @code{.c}
 * static int foo_to_host_cb(const struct usbd_context *const ctx,
 *                           const struct usb_setup_packet *const setup,
 *                           struct net_buf *const buf)
 * {
 *     if (setup->wIndex == WEBUSB_REQ_GET_URL) {
 *         uint8_t index = USB_GET_DESCRIPTOR_INDEX(setup->wValue);
 *
 *         if (index != SAMPLE_WEBUSB_LANDING_PAGE) {
 *             return -ENOTSUP;
 *         }
 *
 *         net_buf_add_mem(buf, &webusb_origin_url,
 *                         MIN(net_buf_tailroom(buf), sizeof(webusb_origin_url)));
 *
 *         return 0;
 *     }
 *
 *     return -ENOTSUP;
 * }
 * @endcode
 */
struct usbd_vreq_node {
	/** Node information for the dlist */
	sys_dnode_t node;
	/** Vendor code (bRequest value) */
	const uint8_t code;
	/** Vendor request callback for device-to-host direction */
	int (*to_host)(const struct usbd_context *const ctx,
		       const struct usb_setup_packet *const setup,
		       struct net_buf *const buf);
	/** Vendor request callback for host-to-device direction */
	int (*to_dev)(const struct usbd_context *const ctx,
		      const struct usb_setup_packet *const setup,
		      const struct net_buf *const buf);
};

/**
 * USBD BOS Device Capability descriptor data
 */
struct usbd_bos_desc_data {
	/** Descriptor usage type (not bDescriptorType) */
	enum usbd_bos_desc_utype utype : 8;
	union {
		struct usbd_vreq_node *const vreq_nd;
	};
};

/**
 * Descriptor node
 *
 * Descriptor node is used to manage descriptors that are not
 * directly part of a structure, such as string or BOS capability descriptors.
 */
struct usbd_desc_node {
	/** slist node struct */
	sys_dnode_t node;
	union {
		struct usbd_str_desc_data str;
		struct usbd_bos_desc_data bos;
	};
	/** Opaque pointer to a descriptor payload */
	const void *const ptr;
	/** Descriptor size in bytes */
	uint8_t bLength;
	/** Descriptor type */
	uint8_t bDescriptorType;
};

/**
 * Device configuration node
 *
 * Configuration node is used to manage device configurations,
 * at least one configuration is required. It does not have an index,
 * instead bConfigurationValue of the descriptor is used for
 * identification.
 */
struct usbd_config_node {
	/** slist node struct */
	sys_snode_t node;
	/** Pointer to configuration descriptor */
	void *desc;
	/** Optional pointer to string descriptor node */
	struct usbd_desc_node *str_desc_nd;
	/** List of registered classes (functions) */
	sys_slist_t class_list;
};

/* TODO: Kconfig option USBD_NUMOF_INTERFACES_MAX? */
#define USBD_NUMOF_INTERFACES_MAX	16U

/**
 * USB device support middle layer runtime state
 *
 * Part of USB device states without suspended and powered
 * states, as it is better to track them separately.
 */
enum usbd_ch9_state {
	USBD_STATE_DEFAULT = 0,
	USBD_STATE_ADDRESS,
	USBD_STATE_CONFIGURED,
};


/**
 * USB device support middle layer runtime data
 */
struct usbd_ch9_data {
	/** Setup packet, up-to-date for the respective control request */
	struct usb_setup_packet setup;
	/** Control type, internally used for stage verification */
	int ctrl_type;
	/** Protocol state of the USB device stack */
	enum usbd_ch9_state state;
	/** Halted endpoints bitmap */
	uint32_t ep_halt;
	/** USB device stack selected configuration */
	uint8_t configuration;
	/** Post status stage work required, e.g. set new device address */
	bool post_status;
	/** Array to track interfaces alternate settings */
	uint8_t alternate[USBD_NUMOF_INTERFACES_MAX];
};

/**
 * @brief USB device speed
 */
enum usbd_speed {
	/** Device supports or is connected to a full speed bus */
	USBD_SPEED_FS,
	/** Device supports or is connected to a high speed bus  */
	USBD_SPEED_HS,
	/** Device supports or is connected to a super speed bus */
	USBD_SPEED_SS,
};

/**
 * USB device support status
 */
struct usbd_status {
	/** USB device support is initialized */
	unsigned int initialized : 1;
	/** USB device support is enabled */
	unsigned int enabled : 1;
	/** USB device is suspended */
	unsigned int suspended : 1;
	/** USB remote wake-up feature is enabled */
	unsigned int rwup : 1;
	/** USB device is self-powered */
	unsigned int self_powered : 1;
	/** USB device speed */
	enum usbd_speed speed : 2;
};

/**
 * @brief Callback type definition for USB device message delivery
 *
 * If the Kconfig option USBD_MSG_DEFERRED_MODE is enabled, then the callback
 * is executed in the context of the system workqueue. Notification messages are
 * stored in a queue and delivered to the callback in sequence.
 *
 * If the Kconfig option USBD_MSG_DEFERRED_MODE is disabled, the callback is
 * executed in the context of the USB device stack thread. The user should make
 * sure that the callback execution does not block or disrupt device stack
 * handling.
 *
 * @param[in] ctx Pointer to USB device support context
 * @param[in] msg Pointer to USB device message
 */
typedef void (*usbd_msg_cb_t)(struct usbd_context *const ctx,
			      const struct usbd_msg *const msg);

/**
 * USB device support runtime context
 *
 * Main structure that organizes all descriptors, configuration,
 * and interfaces. An UDC device must be assigned to this structure.
 */
struct usbd_context {
	/** Name of the USB device */
	const char *name;
	/** Access mutex */
	struct k_mutex mutex;
	/** Pointer to UDC device */
	const struct device *dev;
	/** Notification message recipient callback */
	usbd_msg_cb_t msg_cb;
	/** Middle layer runtime data */
	struct usbd_ch9_data ch9_data;
	/** slist to manage descriptors like string, BOS */
	sys_dlist_t descriptors;
	/** slist to manage Full-Speed device configurations */
	sys_slist_t fs_configs;
	/** slist to manage High-Speed device configurations */
	sys_slist_t hs_configs;
	/** dlist to manage vendor requests with recipient device */
	sys_dlist_t vreqs;
	/** Status of the USB device support */
	struct usbd_status status;
	/** Pointer to Full-Speed device descriptor */
	void *fs_desc;
	/** Pointer to High-Speed device descriptor */
	void *hs_desc;
};

/**
 * @brief Vendor Requests Table
 */
struct usbd_cctx_vendor_req {
	/** Array of vendor requests supported by the class */
	const uint8_t *reqs;
	/** Length of the array */
	uint8_t len;
};

/** USB Class instance registered flag */
#define USBD_CCTX_REGISTERED		0

struct usbd_class_data;

/**
 * @brief USB device support class instance API
 */
struct usbd_class_api {
	/** Feature halt state update handler */
	void (*feature_halt)(struct usbd_class_data *const c_data,
			     uint8_t ep, bool halted);

	/** Configuration update handler */
	void (*update)(struct usbd_class_data *const c_data,
		       uint8_t iface, uint8_t alternate);

	/** USB control request handler to device */
	int (*control_to_dev)(struct usbd_class_data *const c_data,
			      const struct usb_setup_packet *const setup,
			      const struct net_buf *const buf);

	/** USB control request handler to host */
	int (*control_to_host)(struct usbd_class_data *const c_data,
			       const struct usb_setup_packet *const setup,
			       struct net_buf *const buf);

	/** Endpoint request completion event handler */
	int (*request)(struct usbd_class_data *const c_data,
		       struct net_buf *buf, int err);

	/** USB power management handler suspended */
	void (*suspended)(struct usbd_class_data *const c_data);

	/** USB power management handler resumed */
	void (*resumed)(struct usbd_class_data *const c_data);

	/** Start of Frame */
	void (*sof)(struct usbd_class_data *const c_data);

	/** Class associated configuration is selected */
	void (*enable)(struct usbd_class_data *const c_data);

	/** Class associated configuration is disabled */
	void (*disable)(struct usbd_class_data *const c_data);

	/** Initialization of the class implementation */
	int (*init)(struct usbd_class_data *const c_data);

	/** Shutdown of the class implementation */
	void (*shutdown)(struct usbd_class_data *const c_data);

	/** Get function descriptor based on speed parameter */
	void *(*get_desc)(struct usbd_class_data *const c_data,
			  const enum usbd_speed speed);
};

/**
 * @brief USB device support class data
 */
struct usbd_class_data {
	/** Name of the USB device class instance */
	const char *name;
	/** Pointer to USB device stack context structure */
	struct usbd_context *uds_ctx;
	/** Pointer to device support class API */
	const struct usbd_class_api *api;
	/** Supported vendor request table, can be NULL */
	const struct usbd_cctx_vendor_req *v_reqs;
	/** Pointer to private data */
	void *priv;
};

/**
 * @cond INTERNAL_HIDDEN
 *
 * Variables necessary for per speed class management. For each speed (Full,
 * High) there is separate `struct usbd_class_node` pointing to the same
 * `struct usbd_class_data` (because the class can only operate at one speed
 * at a time).
 */
struct usbd_class_node {
	/** Node information for the slist. */
	sys_snode_t node;
	/** Pointer to public class node instance. */
	struct usbd_class_data *const c_data;
	/** Bitmap of all endpoints assigned to the instance.
	 *  The IN endpoints are mapped in the upper halfword.
	 */
	uint32_t ep_assigned;
	/** Bitmap of the enabled endpoints of the instance.
	 *  The IN endpoints are mapped in the upper halfword.
	 */
	uint32_t ep_active;
	/** Bitmap of the bInterfaceNumbers of the class instance */
	uint32_t iface_bm;
	/** Variable to store the state of the class instance */
	atomic_t state;
};

/** @endcond */

/**
 * @brief Get the USB device runtime context under which the class is registered
 *
 * The class implementation must use this function and not access the members
 * of the struct directly.
 *
 * @param[in] c_data Pointer to USB device class data
 *
 * @return Pointer to USB device runtime context
 */
static inline struct usbd_context *usbd_class_get_ctx(const struct usbd_class_data *const c_data)
{
	return c_data->uds_ctx;
}

/**
 * @brief Get class implementation private data
 *
 * The class implementation must use this function and not access the members
 * of the struct directly.
 *
 * @param[in] c_data Pointer to USB device class data
 *
 * @return Pointer to class implementation private data
 */
static inline void *usbd_class_get_private(const struct usbd_class_data *const c_data)
{
	return c_data->priv;
}

/**
 * @brief Define USB device context structure
 *
 * Macro defines a USB device structure needed by the stack to manage its
 * properties and runtime data. The @p vid and @p pid  parameters can also be
 * changed using usbd_device_set_vid() and usbd_device_set_pid().
 *
 * Example of use:
 *
 * @code{.c}
 * USBD_DEVICE_DEFINE(sample_usbd,
 *                    DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)),
 *                    YOUR_VID, YOUR_PID);
 * @endcode
 *
 * @param device_name USB device context name
 * @param udc_dev     Pointer to UDC device structure
 * @param vid         Vendor ID
 * @param pid         Product ID
 */
#define USBD_DEVICE_DEFINE(device_name, udc_dev, vid, pid)		\
	static struct usb_device_descriptor				\
	fs_desc_##device_name = {					\
		.bLength = sizeof(struct usb_device_descriptor),	\
		.bDescriptorType = USB_DESC_DEVICE,			\
		.bcdUSB = sys_cpu_to_le16(USB_SRN_2_0),			\
		.bDeviceClass = USB_BCC_MISCELLANEOUS,			\
		.bDeviceSubClass = 2,					\
		.bDeviceProtocol = 1,					\
		.bMaxPacketSize0 = USB_CONTROL_EP_MPS,			\
		.idVendor = vid,					\
		.idProduct = pid,					\
		.bcdDevice = sys_cpu_to_le16(USB_BCD_DRN),		\
		.iManufacturer = 0,					\
		.iProduct = 0,						\
		.iSerialNumber = 0,					\
		.bNumConfigurations = 0,				\
	};								\
	IF_ENABLED(USBD_SUPPORTS_HIGH_SPEED, (				\
	static struct usb_device_descriptor				\
	hs_desc_##device_name = {					\
		.bLength = sizeof(struct usb_device_descriptor),	\
		.bDescriptorType = USB_DESC_DEVICE,			\
		.bcdUSB = sys_cpu_to_le16(USB_SRN_2_0),			\
		.bDeviceClass = USB_BCC_MISCELLANEOUS,			\
		.bDeviceSubClass = 2,					\
		.bDeviceProtocol = 1,					\
		.bMaxPacketSize0 = 64,					\
		.idVendor = vid,					\
		.idProduct = pid,					\
		.bcdDevice = sys_cpu_to_le16(USB_BCD_DRN),		\
		.iManufacturer = 0,					\
		.iProduct = 0,						\
		.iSerialNumber = 0,					\
		.bNumConfigurations = 0,				\
	};								\
	))								\
	static STRUCT_SECTION_ITERABLE(usbd_context, device_name) = {	\
		.name = STRINGIFY(device_name),				\
		.dev = udc_dev,						\
		.fs_desc = &fs_desc_##device_name,			\
		IF_ENABLED(USBD_SUPPORTS_HIGH_SPEED, (			\
		.hs_desc = &hs_desc_##device_name,			\
		))							\
	}

/**
 * @brief Define USB device configuration
 *
 * USB device requires at least one configuration instance per supported speed.
 * @p attrib is a combination of `USB_SCD_SELF_POWERED` or `USB_SCD_REMOTE_WAKEUP`,
 * depending on which characteristic the USB device should have in this
 * configuration.
 *
 * @param name   Configuration name
 * @param attrib Configuration characteristics. Attributes can also be updated
 *               with usbd_config_attrib_rwup() and usbd_config_attrib_self()
 * @param power  bMaxPower value in 2 mA units. This value can also be set with
 *               usbd_config_maxpower()
 * @param desc_nd Address of the string descriptor node used to describe the
 *                configuration, see USBD_DESC_CONFIG_DEFINE().
 *                String descriptors are optional and the parameter can be NULL.
 */
#define USBD_CONFIGURATION_DEFINE(name, attrib, power, desc_nd)		\
	static struct usb_cfg_descriptor				\
	cfg_desc_##name = {						\
		.bLength = sizeof(struct usb_cfg_descriptor),		\
		.bDescriptorType = USB_DESC_CONFIGURATION,		\
		.wTotalLength = 0,					\
		.bNumInterfaces = 0,					\
		.bConfigurationValue = 1,				\
		.iConfiguration = 0,					\
		.bmAttributes = USB_SCD_RESERVED | (attrib),		\
		.bMaxPower = (power),					\
	};								\
	BUILD_ASSERT((power) < 256, "Too much power");			\
	static struct usbd_config_node name = {				\
		.desc = &cfg_desc_##name,				\
		.str_desc_nd = desc_nd,					\
	}

/**
 * @brief Create a string descriptor node and language string descriptor
 *
 * This macro defines a descriptor node and a string descriptor that,
 * when added to the device context, is automatically used as the language
 * string descriptor zero. Both descriptor node and descriptor are defined with
 * static-storage-class specifier. Default and currently only supported
 * language ID is 0x0409 English (United States).
 * If string descriptors are used, it is necessary to add this descriptor
 * as the first one to the USB device context.
 *
 * @param name Language string descriptor node identifier.
 */
#define USBD_DESC_LANG_DEFINE(name)					\
	static const uint16_t langid_##name = sys_cpu_to_le16(0x0409);	\
	static struct usbd_desc_node name = {				\
		.str = {						\
			.idx = 0,					\
			.utype = USBD_DUT_STRING_LANG,			\
		},							\
		.ptr = &langid_##name,					\
		.bLength = sizeof(struct usb_string_descriptor),	\
		.bDescriptorType = USB_DESC_STRING,			\
	}

/**
 * @brief Create a string descriptor
 *
 * This macro defines a descriptor node and a string descriptor.
 * The string literal passed to the macro should be in the ASCII7 format. It
 * is converted to UTF16LE format on the host request.
 *
 * @param d_name   Internal string descriptor node identifier name
 * @param d_string ASCII7 encoded string literal
 * @param d_utype  String descriptor usage type
 */
#define USBD_DESC_STRING_DEFINE(d_name, d_string, d_utype)			\
	static const uint8_t ascii_##d_name[sizeof(d_string)] = d_string;	\
	static struct usbd_desc_node d_name = {					\
		.str = {							\
			.utype = d_utype,					\
			.ascii7 = true,						\
		},								\
		.ptr = &ascii_##d_name,						\
		.bLength = USB_STRING_DESCRIPTOR_LENGTH(d_string),		\
		.bDescriptorType = USB_DESC_STRING,				\
	}

/**
 * @brief Create a string descriptor node and manufacturer string descriptor
 *
 * This macro defines a descriptor node and a string descriptor that,
 * when added to the device context, is automatically used as the manufacturer
 * string descriptor. Both descriptor node and descriptor are defined with
 * static-storage-class specifier.
 *
 * @param d_name   String descriptor node identifier.
 * @param d_string ASCII7 encoded manufacturer string literal
 */
#define USBD_DESC_MANUFACTURER_DEFINE(d_name, d_string)			\
	USBD_DESC_STRING_DEFINE(d_name, d_string, USBD_DUT_STRING_MANUFACTURER)

/**
 * @brief Create a string descriptor node and product string descriptor
 *
 * This macro defines a descriptor node and a string descriptor that,
 * when added to the device context, is automatically used as the product
 * string descriptor. Both descriptor node and descriptor are defined with
 * static-storage-class specifier.
 *
 * @param d_name   String descriptor node identifier.
 * @param d_string ASCII7 encoded product string literal
 */
#define USBD_DESC_PRODUCT_DEFINE(d_name, d_string)			\
	USBD_DESC_STRING_DEFINE(d_name, d_string, USBD_DUT_STRING_PRODUCT)

/**
 * @brief Create a string descriptor node and serial number string descriptor
 *
 * This macro defines a descriptor node that, when added to the device context,
 * is automatically used as the serial number string descriptor. A valid serial
 * number is obtained from @ref hwinfo_interface whenever this string
 * descriptor is requested.
 *
 * @note The HWINFO driver must be available and the Kconfig option HWINFO
 *       enabled.
 *
 * @param d_name   String descriptor node identifier.
 */
#define USBD_DESC_SERIAL_NUMBER_DEFINE(d_name)					\
	BUILD_ASSERT(IS_ENABLED(CONFIG_HWINFO), "HWINFO not enabled");		\
	static struct usbd_desc_node d_name = {					\
		.str = {							\
			.utype = USBD_DUT_STRING_SERIAL_NUMBER,			\
			.ascii7 = true,						\
			.use_hwinfo = true,					\
		},								\
		.bDescriptorType = USB_DESC_STRING,				\
	}

/**
 * @brief Create a string descriptor node for configuration descriptor
 *
 * This macro defines a descriptor node whose address can be used as an
 * argument for the USBD_CONFIGURATION_DEFINE() macro.
 *
 * @param d_name   String descriptor node identifier.
 * @param d_string ASCII7 encoded configuration description string literal
 */
#define USBD_DESC_CONFIG_DEFINE(d_name, d_string)			\
	USBD_DESC_STRING_DEFINE(d_name, d_string, USBD_DUT_STRING_CONFIG)

/**
 * @brief Define BOS Device Capability descriptor node
 *
 * The application defines a BOS capability descriptor node for descriptors
 * such as USB 2.0 Extension Descriptor.
 *
 * @note It requires Kconfig options USBD_BOS_SUPPORT to be enabled.
 *
 * @param name       Descriptor node identifier
 * @param len        Device Capability descriptor length
 * @param subset     Pointer to a Device Capability descriptor
 */
#define USBD_DESC_BOS_DEFINE(name, len, subset)					\
	BUILD_ASSERT(IS_ENABLED(CONFIG_USBD_BOS_SUPPORT),			\
		     "USB device BOS support is disabled");			\
	static struct usbd_desc_node name = {					\
		.bos = {							\
			.utype = USBD_DUT_BOS_NONE,				\
		},								\
		.ptr = subset,							\
		.bLength = len,							\
		.bDescriptorType = USB_DESC_BOS,				\
	}

/**
 * @brief Define a vendor request with recipient device
 *
 * @note It requires Kconfig options USBD_VREQ_SUPPORT to be enabled.
 *
 * @param name      Vendor request identifier
 * @param vcode     Vendor request code
 * @param vto_host  Vendor callback for to-host direction request
 * @param vto_dev   Vendor callback for to-device direction request
 */
#define USBD_VREQUEST_DEFINE(name, vcode, vto_host, vto_dev)			\
	BUILD_ASSERT(IS_ENABLED(CONFIG_USBD_VREQ_SUPPORT),			\
		     "USB device vendor request support is disabled");		\
	static struct usbd_vreq_node name = {					\
		.code = vcode,							\
		.to_host = vto_host,						\
		.to_dev = vto_dev,						\
	}

/**
 * @brief Define BOS Device Capability descriptor node with vendor request
 *
 * This macro defines a BOS descriptor, usually a platform capability, with a
 * vendor request node.
 *
 * USBD_DESC_BOS_VREQ_DEFINE(bos_vreq_webusb, sizeof(bos_cap_webusb), &bos_cap_webusb,
 *                           SAMPLE_WEBUSB_VENDOR_CODE, webusb_to_host_cb, NULL);
 *
 * @note It requires Kconfig options USBD_VREQ_SUPPORT and USBD_BOS_SUPPORT to
 *       be enabled.
 *
 * @param name      Descriptor node identifier
 * @param len       Device Capability descriptor length
 * @param subset    Pointer to a Device Capability descriptor
 * @param vcode     Vendor request code
 * @param vto_host  Vendor callback for to-host direction request
 * @param vto_dev   Vendor callback for to-device direction request
 */
#define USBD_DESC_BOS_VREQ_DEFINE(name, len, subset, vcode, vto_host, vto_dev)	\
	BUILD_ASSERT(IS_ENABLED(CONFIG_USBD_BOS_SUPPORT),			\
		     "USB device BOS support is disabled");			\
	USBD_VREQUEST_DEFINE(vreq_nd_##name, vcode, vto_host, vto_dev);		\
	static struct usbd_desc_node name = {					\
		.bos = {							\
			.utype = USBD_DUT_BOS_VREQ,				\
			.vreq_nd = &vreq_nd_##name,				\
		},								\
		.ptr = subset,							\
		.bLength = len,							\
		.bDescriptorType = USB_DESC_BOS,				\
	}

/**
 * @brief Define USB device support class data
 *
 * Macro defines class (function) data, as well as corresponding node
 * structures used internally by the stack.
 *
 * @param class_name   Class name
 * @param class_api    Pointer to struct usbd_class_api
 * @param class_priv   Class private data
 * @param class_v_reqs Pointer to struct usbd_cctx_vendor_req
 */
#define USBD_DEFINE_CLASS(class_name, class_api, class_priv, class_v_reqs)	\
	static struct usbd_class_data class_name = {				\
		.name = STRINGIFY(class_name),					\
		.api = class_api,						\
		.v_reqs = class_v_reqs,						\
		.priv = class_priv,						\
	};									\
	static STRUCT_SECTION_ITERABLE_ALTERNATE(				\
		usbd_class_fs, usbd_class_node, class_name##_fs) = {		\
		.c_data = &class_name,						\
	};									\
	IF_ENABLED(USBD_SUPPORTS_HIGH_SPEED, (					\
	static STRUCT_SECTION_ITERABLE_ALTERNATE(				\
		usbd_class_hs, usbd_class_node, class_name##_hs) = {		\
		.c_data = &class_name,						\
	}									\
	))

/** @brief Helper to declare request table of usbd_cctx_vendor_req
 *
 *  @param _reqs Pointer to the vendor request field
 *  @param _len  Number of supported vendor requests
 */
#define VENDOR_REQ_DEFINE(_reqs, _len) \
	{ \
		.reqs = (const uint8_t *)(_reqs), \
		.len = (_len), \
	}

/** @brief Helper to declare supported vendor requests
 *
 *  @param _reqs Variable number of vendor requests
 */
#define USBD_VENDOR_REQ(_reqs...) \
	VENDOR_REQ_DEFINE(((uint8_t []) { _reqs }), \
			  sizeof((uint8_t []) { _reqs }))


/**
 * @brief Add common USB descriptor
 *
 * Add common descriptor like string or BOS Device Capability.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] dn      Pointer to USB descriptor node
 *
 * @return 0 on success, other values on fail.
 */
int usbd_add_descriptor(struct usbd_context *uds_ctx,
			struct usbd_desc_node *dn);

/**
 * @brief Get USB string descriptor index from descriptor node
 *
 * @param[in] desc_nd Pointer to USB descriptor node
 *
 * @return Descriptor index, 0 if descriptor is not part of any device
 */
uint8_t usbd_str_desc_get_idx(const struct usbd_desc_node *const desc_nd);

/**
 * @brief Remove USB string descriptor
 *
 * Remove linked USB string descriptor from any list.
 *
 * @param[in] desc_nd Pointer to USB descriptor node
 */
void usbd_remove_descriptor(struct usbd_desc_node *const desc_nd);

/**
 * @brief Add a USB device configuration
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Speed at which this configuration operates
 * @param[in] cd      Pointer to USB configuration node
 *
 * @return 0 on success, other values on fail.
 */
int usbd_add_configuration(struct usbd_context *uds_ctx,
			   const enum usbd_speed speed,
			   struct usbd_config_node *cd);

/**
 * @brief Register an USB class instance
 *
 * An USB class implementation can have one or more instances.
 * To identify the instances we use device drivers API.
 * Device names have a prefix derived from the name of the class,
 * for example CDC_ACM for CDC ACM class instance,
 * and can also be easily identified in the shell.
 * Class instance can only be registered when the USB device stack
 * is disabled.
 * Registered instances are initialized at initialization
 * of the USB device stack, and the interface descriptors
 * of each instance are adapted to the whole context.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] name    Class instance name
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration value (bConfigurationValue)
 *
 * @return 0 on success, other values on fail.
 */
int usbd_register_class(struct usbd_context *uds_ctx,
			const char *name,
			const enum usbd_speed speed, uint8_t cfg);

/**
 * @brief Register all available USB class instances
 *
 * Register all available instances. Like usbd_register_class, but does not
 * take the instance name and instead registers all available instances.
 *
 * @note This cannot be combined. If your application calls
 * usbd_register_class for any device, configuration number, or instance,
 * either usbd_register_class or this function will fail.
 *
 * There may be situations where a particular function should not be
 * registered, for example, when using the USB DFU implementation, the DFU mode
 * function must be excluded during normal device operation. To do this, the
 * device can pass a blocklist in the form shown below as an optional argument.
 * If the blocklist is not needed, the argument should be NULL.
 *
 * @code{.c}
 * static const char *const blocklist[] = {
 *         "dfu_dfu",
 *         NULL,
 * };
 * @endcode
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration value (bConfigurationValue)
 * @param[in] blocklist Null pointer terminated array of pointers to string
 *                      literals to be used as a block list
 *
 * @return 0 on success, other values on fail.
 */
int usbd_register_all_classes(struct usbd_context *uds_ctx,
			      const enum usbd_speed speed, uint8_t cfg,
			      const char *const blocklist[]);

/**
 * @brief Unregister an USB class instance
 *
 * USB class instance will be removed and will not appear
 * on the next start of the stack. Instance can only be unregistered
 * when the USB device stack is disabled.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] name    Class instance name
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration value (bConfigurationValue)
 *
 * @return 0 on success, other values on fail.
 */
int usbd_unregister_class(struct usbd_context *uds_ctx,
			  const char *name,
			  const enum usbd_speed speed, uint8_t cfg);

/**
 * @brief Unregister all available USB class instances
 *
 * Unregister all available instances. Like usbd_unregister_class, but does not
 * take the instance name and instead unregisters all available instances.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration value (bConfigurationValue)
 *
 * @return 0 on success, other values on fail.
 */
int usbd_unregister_all_classes(struct usbd_context *uds_ctx,
				const enum usbd_speed speed, uint8_t cfg);

/**
 * @brief Register USB notification message callback
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] cb      Pointer to message callback function
 *
 * @return 0 on success, other values on fail.
 */
int usbd_msg_register_cb(struct usbd_context *const uds_ctx,
			 const usbd_msg_cb_t cb);

/**
 * @brief Initialize USB device
 *
 * Initialize USB device descriptors and configuration,
 * initialize USB device controller.
 * Class instances should be registered before they are involved.
 * However, the stack should also initialize without registered instances,
 * even if the host would complain about missing interfaces.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return 0 on success, other values on fail.
 */
int usbd_init(struct usbd_context *uds_ctx);

/**
 * @brief Enable the USB device support and registered class instances
 *
 * This function enables the USB device support.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return 0 on success, other values on fail.
 */
int usbd_enable(struct usbd_context *uds_ctx);

/**
 * @brief Disable the USB device support
 *
 * This function disables the USB device support.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return 0 on success, other values on fail.
 */
int usbd_disable(struct usbd_context *uds_ctx);

/**
 * @brief Shutdown the USB device support
 *
 * This function completely disables the USB device support.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return 0 on success, other values on fail.
 */
int usbd_shutdown(struct usbd_context *const uds_ctx);

/**
 * @brief Halt endpoint
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] ep      Endpoint address
 *
 * @return 0 on success, or error from udc_ep_set_halt()
 */
int usbd_ep_set_halt(struct usbd_context *uds_ctx, uint8_t ep);

/**
 * @brief Clear endpoint halt
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] ep      Endpoint address
 *
 * @return 0 on success, or error from udc_ep_clear_halt()
 */
int usbd_ep_clear_halt(struct usbd_context *uds_ctx, uint8_t ep);

/**
 * @brief Checks whether the endpoint is halted.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] ep      Endpoint address
 *
 * @return true if endpoint is halted, false otherwise
 */
bool usbd_ep_is_halted(struct usbd_context *uds_ctx, uint8_t ep);

/**
 * @brief Allocate buffer for USB device request
 *
 * Allocate a new buffer from controller's driver buffer pool.
 *
 * @param[in] c_data Pointer to USB device class data
 * @param[in] ep     Endpoint address
 * @param[in] size   Size of the request buffer
 *
 * @return pointer to allocated request or NULL on error.
 */
struct net_buf *usbd_ep_buf_alloc(const struct usbd_class_data *const c_data,
				  const uint8_t ep, const size_t size);

/**
 * @brief Queue USB device control request
 *
 * Add control request to the queue.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] buf     Pointer to UDC request buffer
 *
 * @return 0 on success, all other values should be treated as error.
 */
int usbd_ep_ctrl_enqueue(struct usbd_context *const uds_ctx,
			 struct net_buf *const buf);

/**
 * @brief Queue USB device request
 *
 * Add request to the queue.
 *
 * @param[in] c_data   Pointer to USB device class data
 * @param[in] buf    Pointer to UDC request buffer
 *
 * @return 0 on success, or error from udc_ep_enqueue()
 */
int usbd_ep_enqueue(const struct usbd_class_data *const c_data,
		    struct net_buf *const buf);

/**
 * @brief Remove all USB device controller requests from endpoint queue
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] ep      Endpoint address
 *
 * @return 0 on success, or error from udc_ep_dequeue()
 */
int usbd_ep_dequeue(struct usbd_context *uds_ctx, const uint8_t ep);

/**
 * @brief Free USB device request buffer
 *
 * Put the buffer back into the request buffer pool.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] buf     Pointer to UDC request buffer
 *
 * @return 0 on success, all other values should be treated as error.
 */
int usbd_ep_buf_free(struct usbd_context *uds_ctx, struct net_buf *buf);

/**
 * @brief Checks whether the USB device controller is suspended.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return true if endpoint is halted, false otherwise
 */
bool usbd_is_suspended(struct usbd_context *uds_ctx);

/**
 * @brief Initiate the USB remote wakeup (TBD)
 *
 * @return 0 on success, other values on fail.
 */
int usbd_wakeup_request(struct usbd_context *uds_ctx);

/**
 * @brief Set the self-powered status of the USB device
 *
 * The status is used in the Self Powered field of the Get Status request
 * response to indicate whether the device is currently self-powered.
 *
 * @param[in] uds_ctx Pointer to a device context
 * @param[in] status Sets self-powered status if true, clears it otherwise
 */
void usbd_self_powered(struct usbd_context *uds_ctx, const bool status);

/**
 * @brief Get actual device speed
 *
 * @param[in] uds_ctx Pointer to a device context
 *
 * @return Actual device speed
 */
enum usbd_speed usbd_bus_speed(const struct usbd_context *const uds_ctx);

/**
 * @brief Get highest speed supported by the controller
 *
 * @param[in] uds_ctx Pointer to a device context
 *
 * @return Highest supported speed
 */
enum usbd_speed usbd_caps_speed(const struct usbd_context *const uds_ctx);

/**
 * @brief Set USB device descriptor value bcdUSB
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Speed for which the bcdUSB should be set
 * @param[in] bcd     bcdUSB value
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_set_bcd_usb(struct usbd_context *const uds_ctx,
			    const enum usbd_speed speed, const uint16_t bcd);

/**
 * @brief Set USB device descriptor value idVendor
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] vid     idVendor value
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_set_vid(struct usbd_context *const uds_ctx,
			 const uint16_t vid);

/**
 * @brief Set USB device descriptor value idProduct
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] pid     idProduct value
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_set_pid(struct usbd_context *const uds_ctx,
			const uint16_t pid);

/**
 * @brief Set USB device descriptor value bcdDevice
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] bcd     bcdDevice value
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_set_bcd_device(struct usbd_context *const uds_ctx,
			       const uint16_t bcd);

/**
 * @brief Set USB device descriptor code triple Base Class, SubClass, and Protocol
 *
 * @param[in] uds_ctx    Pointer to USB device support context
 * @param[in] speed      Speed for which the code triple should be set
 * @param[in] base_class bDeviceClass value
 * @param[in] subclass   bDeviceSubClass value
 * @param[in] protocol   bDeviceProtocol value
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_set_code_triple(struct usbd_context *const uds_ctx,
				const enum usbd_speed speed,
				const uint8_t base_class,
				const uint8_t subclass, const uint8_t protocol);

/**
 * @brief Setup USB device configuration attribute Remote Wakeup
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration number
 * @param[in] enable  Sets attribute if true, clears it otherwise
 *
 * @return 0 on success, other values on fail.
 */
int usbd_config_attrib_rwup(struct usbd_context *const uds_ctx,
			    const enum usbd_speed speed,
			    const uint8_t cfg, const bool enable);

/**
 * @brief Setup USB device configuration attribute Self-powered
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration number
 * @param[in] enable  Sets attribute if true, clears it otherwise
 *
 * @return 0 on success, other values on fail.
 */
int usbd_config_attrib_self(struct usbd_context *const uds_ctx,
			    const enum usbd_speed speed,
			    const uint8_t cfg, const bool enable);

/**
 * @brief Setup USB device configuration power consumption
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] speed   Configuration speed
 * @param[in] cfg     Configuration number
 * @param[in] power   Maximum power consumption value (bMaxPower)
 *
 * @return 0 on success, other values on fail.
 */
int usbd_config_maxpower(struct usbd_context *const uds_ctx,
			 const enum usbd_speed speed,
			 const uint8_t cfg, const uint8_t power);

/**
 * @brief Check that the controller can detect the VBUS state change.
 *
 * This can be used in a generic application to explicitly handle the VBUS
 * detected event after usbd_init(). For example, to call usbd_enable() after a
 * short delay to give the PMIC time to detect the bus, or to handle cases
 * where usbd_enable() can only be called after a VBUS detected event.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 *
 * @return true if controller can detect VBUS state change, false otherwise
 */
bool usbd_can_detect_vbus(struct usbd_context *const uds_ctx);

/**
 * @brief Register an USB vendor request with recipient device
 *
 * The vendor request with the recipient device applies to all configurations
 * within the device.
 *
 * @param[in] uds_ctx Pointer to USB device support context
 * @param[in] vreq_nd Pointer to vendor request node
 *
 * @return 0 on success, other values on fail.
 */
int usbd_device_register_vreq(struct usbd_context *const uds_ctx,
			      struct usbd_vreq_node *const vreq_nd);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_USBD_H_ */
