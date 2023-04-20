/*
 * Copyright (c) 2021 Fingerprint Cards AB <tech@fingerprints.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include <stdio.h>
#include <stdlib.h>
#include "fpi-byte-reader.h"
#include <stdint.h>
#include <stdbool.h>

#define FPC_CONFIG_MAX_NR_TEMPLATES 10
#define FPC_TA_BIO_DB_RDONLY 0
#define FPC_TA_BIO_DB_WRONLY 1

//#include "fpclib_api.h"
typedef struct fpc_enclave fpc_enclave_t;
typedef struct fpc_tac_shared_mem {
    void* addr;
} fpc_tac_shared_mem_t;


typedef enum fpc_enclave_status {
    FPC_ENCLAVE_ACTIVE,
    FPC_ENCLAVE_LOST
} fpc_enclave_status_t;

enum {
    FPC_TLS_IN_PROGRESS,
    FPC_TLS_HANDSHAKE_COMPLETE
};
typedef int fpc_tls_status_t;
typedef struct fpc_tac fpc_tac_t;

struct fpc_tee {
    fpc_tac_t* tac;
    fpc_tac_shared_mem_t* shared_buffer;
};


typedef struct fpc_tee fpc_tee_t;

struct fpc_tee_bio {
    fpc_tee_t tee;
};
typedef struct fpc_tee_bio fpc_tee_bio_t;





#define TEMPLATE_ID_SIZE (32)
#define MAX_FW_VERSION_STR_LEN (16)

#define FPC_CMD_INIT (0x01)
#define FPC_CMD_ARM (0x02)
#define FPC_CMD_ABORT (0x03)
#define FPC_CMD_INDICATE_S_STATE (0x08)
#define FPC_CMD_GET_IMG (0x09)
#define FPC_CMD_GET_KPI (0x0C)

#define FPC_CMD_LOAD_DB (0x60)
#define FPC_CMD_STORE_DB (0x61)
#define FPC_CMD_DELETE_DB (0x62)
#define FPC_CMD_DELETE_TEMPLATE (0x63)
#define FPC_CMD_BEGIN_ENROL (0x67)
#define FPC_CMD_ENROL (0x68)
#define FPC_CMD_END_ENROL (0x69)
#define FPC_CMD_BIND_IDENTITY (0x6A)
#define FPC_CMD_IDENTIFY (0x6B)
#define FPC_CMD_ENUM (0x70)

#define FPC_EVT_INIT_RESULT (0x02)
#define FPC_EVT_FINGER_DWN (0x06)
#define FPC_EVT_IMG (0x08)
#define FPC_EVT_FID_DATA (0x31)

#define FPC_DB_ID_LEN (16)

#define FPC_IDENTITY_TYPE_WILDCARD (0x1)
#define FPC_IDENTITY_TYPE_RESERVED (0x3)
#define FPC_IDENTITY_WILDCARD (0x25066282)
#define FPC_SUBTYPE_ANY (0xFF)
#define FPC_SUBTYPE_RESERVED (0xF5)

#define FPC_CAPTUREID_RESERVED (0x701100F)
#define FPC_SESSIONID_RESERVED (0x0077FF12)
#define FPC_TEMPLATES_MAX (10)
#define SECURITY_MAX_SID_SIZE (68)

#define FPC_HOST_MS_S0 (0x10)
#define FPC_HOST_MS_SX (0x11)

#define FP_COMPONENT "fpcmoh"
#define MAX_ENROLL_SAMPLES (12)
#define CTRL_TIMEOUT (1000)
#define DATA_TIMEOUT (5000)

/* Usb port setting */
#define EP_IN (2 | FPI_USB_ENDPOINT_IN)
#define EP_IN_MAX_BUF_SIZE (2048)


G_DECLARE_FINAL_TYPE (FpiDeviceFpcMoh, fpi_device_fpcmoh, FPI,
                      DEVICE_FPCMOH, FpDevice);

typedef struct _FPC_FID_DATA
{
  guint32 identity_type;
  guint32 reserved;
  guint32 identity_size;
  guint32 subfactor;
  guint8  data[SECURITY_MAX_SID_SIZE];
} FPC_FID_DATA, *PFPC_FID_DATA;

typedef struct _FPC_LOAD_DB
{
  gint32  status;
  guint32 reserved;
  guint32 database_id_size;
  guint8  data[FPC_DB_ID_LEN];
} FPC_LOAD_DB, *PFPC_LOAD_DB;

typedef union _FPC_DELETE_DB
{
  guint32 reserved;
  guint32 database_id_size;
  guint8  data[FPC_DB_ID_LEN];
} FPC_DB_OP, *PFPC_DB_OP;

typedef struct _FPC_BEGIN_ENROL
{
  gint32  status;
  guint32 reserved1;
  guint32 reserved2;
} FPC_BEGIN_ENROL, *PFPC_BEGIN_ENROL;

typedef struct _FPC_ENROL
{
  gint32  status;
  guint32 remaining;
} FPC_ENROL, *PFPC_ENROL;

typedef struct _FPC_END_ENROL
{
  gint32  status;
  guint32 fid;
} FPC_END_ENROL, *PFPC_END_ENROL;

typedef struct _FPC_IDENTIFY
{
  gint32  status;
  guint32 identity_type;
  guint32 identity_offset;
  guint32 identity_size;
  guint32 subfactor;
  guint8  data[SECURITY_MAX_SID_SIZE];
} FPC_IDENTIFY, *PFPC_IDENTIFY;

#pragma pack(push, 1)
typedef struct
{
  guint32 cmdid;
  guint32 length;
  guint32 status;
} evt_hdr_t;

typedef struct
{
  evt_hdr_t hdr;
  guint16   sensor;
  guint16   hw_id;
  guint16   img_w;
  guint16   img_h;
  guint8    fw_version[MAX_FW_VERSION_STR_LEN];
  guint16   fw_capabilities;
} evt_initiated_t;
#pragma pack(pop)

typedef struct
{
  guint8  subfactor;
  guint32 identity_type;
  guint32 identity_size;
  guint8  identity[SECURITY_MAX_SID_SIZE];
} __attribute__((packed)) fpc_fid_data_t;

typedef struct
{
  evt_hdr_t      hdr;
  gint           status;
  guint32        num_ids;
  fpc_fid_data_t fid_data[FPC_TEMPLATES_MAX];
} __attribute__((packed)) evt_enum_fids_t;

typedef struct _fp_cmd_response
{
  union
  {
    evt_hdr_t       evt_hdr;
    evt_initiated_t evt_inited;
    evt_enum_fids_t evt_enum_fids;
  };
} fpc_cmd_response_t, *pfpc_cmd_response_t;

enum {
  FPC_ENROL_STATUS_COMPLETED = 0,
  FPC_ENROL_STATUS_PROGRESS = 1,
  FPC_ENROL_STATUS_FAILED_COULD_NOT_COMPLETE = 2,
  FPC_ENROL_STATUS_FAILED_ALREADY_ENROLED = 3,
  FPC_ENROL_STATUS_IMAGE_LOW_COVERAGE = 4,
  FPC_ENROL_STATUS_IMAGE_TOO_SIMILAR = 5,
  FPC_ENROL_STATUS_IMAGE_LOW_QUALITY = 6,
};

typedef enum {
  FPC_CMDTYPE_UNKNOWN = 0,
  FPC_CMDTYPE_TO_DEVICE,
  FPC_CMDTYPE_TO_DEVICE_EVTDATA,
  FPC_CMDTYPE_FROM_DEVICE,
} FpcCmdType;

typedef enum {
  FP_CMD_SEND = 0,
  FP_CMD_GET_DATA,
  FP_CMD_SUSPENDED,
  FP_CMD_RESUME,
  FP_CMD_NUM_STATES,
} FpCmdState;

typedef enum {
  FPC_INIT_CMD_ABORT = 0,
  FPC_INIT_CMD_INIT,
  FPC_INIT_WAIT4INIT_RESULT,
  FPC_INIT_WAKE_UP,
  FPC_INIT_INIT,
  FPC_INIT_TLS_CONNECT,
  FPC_INIT_TLS_HANDSHAKE_START,
  FPC_INIT_TLS_HANDSHAKE_WAIT4HELLO,
  FPC_INIT_TLS_HANDSHAKE_PROCESS,
  FPC_INIT_TLS_HANDSHAKE_WRITE,
  FPC_INIT_TLS_HANDSHAKE_WROTEN,
  FPC_INIT_TEE_INIT,
  FPC_INIT_NUM_STATES,
} FpInitState;

typedef enum {
  FP_ENROLL_BEGIN = 0,
  FP_ENROLL_CAPTURE,
  FP_ENROLL_WAIT4FINGERDOWN,

  FP_ENROLL_GET_IMG,

  FP_ENROLL_WAIT4IMG_SEQ1,
  FP_ENROLL_WAIT4IMG_SEQ2,
  FP_ENROLL_WAIT4IMG_SEQ3,
  FP_ENROLL_WAIT4IMG_SEQ4,
  FP_ENROLL_WAIT4IMG_SEQ5,
  FP_ENROLL_WAIT4IMG_SEQ6,
  FP_ENROLL_WAIT4IMG_SEQ7,
  FP_ENROLL_WAIT4IMG_SEQ8,
  FP_ENROLL_WAIT4IMG_SEQ9,
  FP_ENROLL_WAIT4IMG_SEQ10,
  FP_ENROLL_WAIT4IMG_SEQ11,
  FP_ENROLL_SEND_DEAD_PIXEL,
  FP_ENROLL_READ_DEAD_PIXEL,

  FP_ENROLL_BINDID,
  FP_ENROLL_END,
  FP_ENROLL_SUSPENDED,
  FP_ENROLL_RESUME,
  FP_ENROLL_DISCARD,
  FP_ENROLL_NUM_STATES,
} FpEnrollState;

typedef enum {
  FP_VERIFY_CAPTURE = 0,
  FP_VERIFY_WAIT4FINGERDOWN,
  FP_VERIFY_GET_IMG,
  FP_VERIFY_WAIT4IMG_SEQ1,
  FP_VERIFY_WAIT4IMG_SEQ2,
  FP_VERIFY_WAIT4IMG_SEQ3,
  FP_VERIFY_WAIT4IMG_SEQ4,
  FP_VERIFY_WAIT4IMG_SEQ5,
  FP_VERIFY_WAIT4IMG_SEQ6,
  FP_VERIFY_WAIT4IMG_SEQ7,
  FP_VERIFY_WAIT4IMG_SEQ8,
  FP_VERIFY_WAIT4IMG_SEQ9,
  FP_VERIFY_WAIT4IMG_SEQ10,
  FP_VERIFY_WAIT4IMG_SEQ11,
  FP_VERIFY_IDENTIFY,
  FP_VERIFY_SUSPENDED,
  FP_VERIFY_RESUME,
  FP_VERIFY_CANCEL,
  FP_VERIFY_NUM_STATES,
} FpVerifyState;

typedef enum {
  FP_CLEAR_DELETE_DB = 0,
  FP_CLEAR_CREATE_DB,
  FP_CLEAR_NUM_STATES,
} FpClearState;

typedef struct _DEVICE_CONTEXT
{
  gboolean            initialized;
  struct fpc_tee     *tee_handle;
  struct fpc_tee_bio *bio;
  guint32             img_w;
  guint32             img_h;
  guint8             *tls_data;
  guint32             tls_data_len;
  guint32             yasc_session_id;
  fpc_enclave_t      *enclave;
  fpc_tls_status_t    tls_status;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;


typedef fpc_enclave_t * fpc_create_enclave_t (void);
typedef int32_t fpc_start_enclave_t (fpc_enclave_t *);
typedef int32_t fpc_destroy_enclave_t (fpc_enclave_t *enclave);
typedef int32_t fpc_shutdown_enclave_t (fpc_enclave_t *enclave);
//
typedef int32_t fpc_enclave_init_t (fpc_enclave_t *enclave, uint16_t hwid);
typedef int32_t fpc_enclave_handle_tls_connection_t (fpc_enclave_t *enclave, uint8_t *sealed_tls_key, uint32_t sealed_tls_key_len);
typedef int32_t fpc_enclave_tls_init_handshake_t (fpc_enclave_t *enclave);
typedef int32_t fpc_enclave_get_tls_status_t (fpc_enclave_t *enclave, fpc_tls_status_t *status);
typedef int32_t fpc_enclave_get_status_t (fpc_enclave_t *enclave, fpc_enclave_status_t *status);
typedef int32_t fpc_enclave_process_data_t (fpc_enclave_t *enclave);

typedef fpc_tee_bio_t* fpc_tee_bio_init_t (fpc_tee_t* tee);
typedef void fpc_tee_bio_release_t (fpc_tee_bio_t* tee);
typedef int32_t fpc_tee_begin_enroll_t (fpc_tee_bio_t* tee);
typedef int32_t fpc_tee_enroll_t (fpc_tee_bio_t* tee, uint32_t* remaining);
typedef int32_t fpc_tee_end_enroll_t (fpc_tee_bio_t* tee, uint32_t* id);
typedef int32_t fpc_tee_identify_t (fpc_tee_bio_t* tee, uint32_t* id);
typedef int32_t fpc_tee_update_template_t (fpc_tee_bio_t* tee, uint32_t* update);
typedef int32_t fpc_tee_get_finger_ids_t (fpc_tee_bio_t* tee, uint32_t* size, uint32_t* ids);
typedef int32_t fpc_tee_load_empty_db_t (fpc_tee_bio_t* tee);
typedef int32_t fpc_tee_get_db_blob_size_t (fpc_tee_t* tee, size_t *blob_size);
typedef int32_t fpc_tee_db_open_t (fpc_tee_t *tee, uint32_t mode, uint32_t size);
typedef int32_t fpc_tee_db_close_t (fpc_tee_t *tee);
typedef int32_t fpc_tee_send_db_read_commands_t (fpc_tee_t* tee, uint8_t *blob, size_t blob_size);
typedef int32_t fpc_tee_send_db_write_commands_t (fpc_tee_t* tee, const uint8_t *blob, size_t blob_size);
typedef int32_t fpc_tls_buff_init_t (void);
typedef int32_t fpc_tls_buff_release_t (void);
typedef int32_t fpc_tls_buff_clear_t (void);
typedef int32_t fpc_tls_buff_put_t (uint8_t *data, uint32_t len);
typedef int32_t fpc_tls_write_buff_init_t (void);
typedef int32_t fpc_tls_write_buff_release_t (void);
typedef int32_t fpc_tls_write_buff_clear_t (void);
typedef uint8_t fpc_tls_write_buff_is_empty_t (void);
typedef uint32_t fpc_tls_write_buff_get_t (uint8_t *o_data, uint32_t len);
typedef int32_t fpc_secure_random_t(uint8_t* data, uint32_t data_size);
typedef fpc_tee_t *fpc_tee_init_t(void);

struct _FpiDeviceFpcMoh
{
  FpDevice        parent;
  FpiSsm         *task_ssm;
  FpiSsm         *enroll_ssm;
  FpiSsm         *identify_ssm;

  FpiSsm         *cmd_ssm;
  gboolean        cmd_cancelable;
  gboolean        cmd_suspended;
  guint32         enroll_count;
  gint            enroll_stage;
  gint            immobile_stage;
  gint            max_enroll_stage;
  gint            max_immobile_stage;
  PDEVICE_CONTEXT dev_ctx;
  GCancellable   *interrupt_cancellable;

  fpc_create_enclave_t *fpc_create_enclave;
  fpc_start_enclave_t  *fpc_start_enclave;
  fpc_destroy_enclave_t *fpc_destroy_enclave;
  fpc_shutdown_enclave_t *fpc_shutdown_enclave;
  fpc_enclave_init_t *fpc_enclave_init;
  fpc_enclave_handle_tls_connection_t *fpc_enclave_handle_tls_connection;
  fpc_enclave_tls_init_handshake_t *fpc_enclave_tls_init_handshake;
  fpc_enclave_get_tls_status_t *fpc_enclave_get_tls_status;
  fpc_enclave_get_status_t *fpc_enclave_get_status;
  fpc_enclave_process_data_t *fpc_enclave_process_data;

  fpc_tee_bio_init_t *fpc_tee_bio_init;
  fpc_tee_bio_release_t *fpc_tee_bio_release;
  fpc_tee_begin_enroll_t *fpc_tee_begin_enroll;
  fpc_tee_enroll_t *fpc_tee_enroll;
  fpc_tee_end_enroll_t *fpc_tee_end_enroll;
  fpc_tee_identify_t *fpc_tee_identify;
  fpc_tee_update_template_t *fpc_tee_update_template;
  fpc_tee_get_finger_ids_t *fpc_tee_get_finger_ids;

  fpc_tee_load_empty_db_t *fpc_tee_load_empty_db;
  fpc_tee_get_db_blob_size_t *fpc_tee_get_db_blob_size;
  fpc_tee_db_open_t *fpc_tee_db_open;
  fpc_tee_db_close_t *fpc_tee_db_close;
  fpc_tee_send_db_read_commands_t *fpc_tee_send_db_read_commands;
  fpc_tee_send_db_write_commands_t *fpc_tee_send_db_write_commands;
  fpc_tls_buff_init_t *fpc_tls_buff_init;
  fpc_tls_buff_release_t *fpc_tls_buff_release;
  fpc_tls_buff_clear_t *fpc_tls_buff_clear;
  fpc_tls_buff_put_t *fpc_tls_buff_put;
  fpc_tls_write_buff_init_t *fpc_tls_write_buff_init;
  fpc_tls_write_buff_release_t *fpc_tls_write_buff_release;
  fpc_tls_write_buff_clear_t *fpc_tls_write_buff_clear;
  fpc_tls_write_buff_is_empty_t *fpc_tls_write_buff_is_empty;
  fpc_tls_write_buff_get_t *fpc_tls_write_buff_get;
  fpc_secure_random_t *fpc_secure_random;
  fpc_tee_init_t *fpc_tee_init;
};
