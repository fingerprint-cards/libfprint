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

#include "drivers_api.h"
#include "fpc.h"
#include <byteswap.h>
#include <dlfcn.h>

G_DEFINE_TYPE (FpiDeviceFpcMoh, fpi_device_fpcmoh, FP_TYPE_DEVICE);

typedef void (*SynCmdMsgCallback) (FpiDeviceFpcMoh *self,
                                   guint8          *resp,
                                   GError          *error);
typedef struct
{
  FpcCmdType        cmdtype;
  guint8            request;
  guint16           value;
  guint16           index;
  guint8           *data;
  gsize             data_len;
  SynCmdMsgCallback callback;
} CommandData;

static const FpIdEntry id_table[] = {
  { .vid = 0x10A5,  .pid = 0x9800,  },
  { .vid = 0,  .pid = 0,  .driver_data = 0 },   /* terminating entry */
};

static void
fpc_dev_release_interface (FpiDeviceFpcMoh *self,
                           GError          *error)
{
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, &error);
  fpi_device_close_complete (FP_DEVICE (self), error);
}

static gboolean
parse_print_data (GVariant      *data,
                  const guint8 **blob,
                  gsize         *blob_size,
                  const guint8 **user_id,
                  gsize         *user_id_len)
{
  g_autoptr(GVariant) user_id_var = NULL;
  g_autoptr(GVariant) blob_var = NULL;

  g_return_val_if_fail (data, FALSE);
  g_return_val_if_fail (user_id, FALSE);
  g_return_val_if_fail (user_id_len, FALSE);

  *user_id = NULL;
  *user_id_len = 0;
  *blob = NULL;
  *blob_size = 0;

  if (!g_variant_check_format_string (data, "(@ay@ay)", FALSE))
    return FALSE;

  fp_dbg ("%s: enter", G_STRFUNC);

  g_variant_get (data,
                 "(@ay@ay)",
                 &blob_var,
                 &user_id_var);

  fp_dbg ("%s: blob_var %p, user_id_var %p", G_STRFUNC, blob_var, user_id_var);
  *blob = g_variant_get_fixed_array (blob_var, blob_size, 1);
  fp_dbg ("%s: blob_size %lu", G_STRFUNC, *blob_size);

  *user_id = g_variant_get_fixed_array (user_id_var, user_id_len, 1);
  fp_dbg ("%s: user_id_len %lu", G_STRFUNC, *user_id_len);

  return TRUE;
}


static void
fpc_write_ctrl (FpiSsm                *ssm,
                FpDevice              *dev,
                guint8                 cmdid,
                guint8                 value,
                guint8                *data,
                guint32                data_len,
                FpiUsbTransferCallback callback,
                gpointer               user_data)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fp_dbg ("send cmdid %02x", cmdid);
  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 cmdid,
                                 value,
                                 0x00,
                                 data_len);
  if (data && data_len > 0)
    memcpy (transfer->buffer, data, data_len);

  transfer->ssm = ssm;

  fpi_usb_transfer_submit (transfer, CTRL_TIMEOUT, NULL,
                           callback, user_data);
}

static void
fpc_read_dead_pixels (FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer unused_data, GError *error)
{
  fp_dbg ("enter --> %s", G_STRFUNC);
  uint32_t remaining_samples;
  guint32 g_finger_id = 0;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  int32_t result = 0;
  int ssm_state;
  static guint32 expect_len = 0;
  static guint32 received_len = 0;

  g_return_if_fail (self);
  g_return_if_fail (transfer->ssm);
  g_return_if_fail (transfer->buffer);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (transfer->actual_length <= sizeof (evt_hdr_t) && expect_len == 0)
    {
      fp_err ("%s: len %lu err!", G_STRFUNC, transfer->actual_length);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }

  if (expect_len > received_len)
    {
      self->fpc_tls_buff_put (transfer->buffer, transfer->actual_length);
      received_len += transfer->actual_length;
      fp_dbg ("%s: received_len %u, expect len %u", G_STRFUNC, received_len, expect_len);
    }

  if (expect_len == 0)
    {
      //tls header
      evt_hdr_t *evt = (evt_hdr_t *) transfer->buffer;
      guint32 evt_id = GUINT32_FROM_BE (evt->cmdid);
      guint32 img_len = GUINT32_FROM_BE (evt->length);
      fp_dbg ("%s: evtid %u, img_len %u, enroll_cnt %u", G_STRFUNC, evt_id, img_len, self->enroll_count);

      self->fpc_tls_buff_clear ();
      self->fpc_tls_buff_put (transfer->buffer + sizeof (evt_hdr_t), transfer->actual_length - sizeof (evt_hdr_t));

      expect_len = img_len;
      received_len += transfer->actual_length;
    }

  if (received_len >= expect_len)
    {
      received_len = 0;
      expect_len = 0;
      self->fpc_enclave_process_data (self->dev_ctx->enclave);

      if (self->enroll_count++ < MAX_ENROLL_SAMPLES - 1)
        {
          result = self->fpc_tee_enroll (self->dev_ctx->bio, &remaining_samples);
          if (result < 0 )
            {
              fp_err ("%s: enoll fail! rst %d", G_STRFUNC, result);
              fpi_ssm_mark_failed (transfer->ssm,
                                   fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
              return;
            }

          if (0 == result)
            {
              fp_warn ("%s: unexpected finished %d! fail!", G_STRFUNC, result);
              fpi_ssm_mark_failed (transfer->ssm,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));

              return;
            }

          if (1 != result && 5 != result)
            {
              fp_warn ("%s: unexpected finger! result %d try again!", G_STRFUNC, result);
              if (self->enroll_count > 0)
                self->enroll_count--;

              fpi_device_enroll_progress (device,
                                          self->enroll_count,
                                          NULL,
                                          fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));

              fpi_ssm_jump_to_state (transfer->ssm, FP_ENROLL_CAPTURE);
              return;
            }

          fpi_device_enroll_progress (device, self->enroll_count, NULL, NULL);
          fpi_ssm_jump_to_state (transfer->ssm, FP_ENROLL_CAPTURE);
        }
      else
        {
          result = self->fpc_tee_end_enroll (self->dev_ctx->bio, &g_finger_id);
          fp_dbg ("%s: fpc_tee_end_enroll result %d, fingerid %u", G_STRFUNC, result, g_finger_id);
          fpi_ssm_next_state (transfer->ssm);
        }
    }
  else
    {
      ssm_state = fpi_ssm_get_cur_state (transfer->ssm);
      fpi_ssm_jump_to_state (transfer->ssm, ssm_state);
    }

  fp_dbg ("exit <-- %s", G_STRFUNC);
}

static void
fpc_enroll_wait4finger_cb (FpiUsbTransfer *transfer,
                           FpDevice       *device,
                           gpointer        user_data,
                           GError         *error)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  fp_dbg ("enter %s, suspend %u", G_STRFUNC, self->cmd_suspended);

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) && (self->cmd_suspended))
    {
      g_error_free (error);
      fpi_ssm_jump_to_state (transfer->ssm, FP_ENROLL_SUSPENDED);
      return;
    }

  if (error)
    {
      fp_dbg ("%s err message %s", G_STRFUNC, error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc_verify_wait4finger_cb (FpiUsbTransfer *transfer,
                           FpDevice       *device,
                           gpointer        user_data,
                           GError         *error)
{
  fp_dbg ("enter %s", G_STRFUNC);

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) && (FPI_DEVICE_FPCMOH (device)->cmd_suspended))
    {
      g_error_free (error);
      fpi_ssm_jump_to_state (transfer->ssm, FP_VERIFY_SUSPENDED);
      return;
    }

  if (error)
    {
      fp_dbg ("%s err message %s", G_STRFUNC, error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
sm_wait4finger (FpiSsm                *ssm,
                FpDevice              *dev,
                FpiUsbTransferCallback callback)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_dbg ("enter %s", G_STRFUNC);
  transfer->ssm = ssm;

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           callback,
                           NULL);
}

static void
fpc_ssm_img_read_cb (FpiUsbTransfer *transfer, FpDevice *device,
                     gpointer data, GError *error)
{
  fp_dbg ("enter --> %s", G_STRFUNC);

  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  int ssm_state = 0;
  static guint32 expect_len = 0;
  static guint32 received_len = 0;

  g_return_if_fail (self);
  g_return_if_fail (transfer->ssm);
  g_return_if_fail (transfer->buffer);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length <= sizeof (evt_hdr_t) && expect_len == 0)
    {
      fp_err ("%s: len %lu err!", G_STRFUNC, transfer->actual_length);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }

  if (expect_len > received_len)
    {
      self->fpc_tls_buff_put (transfer->buffer, transfer->actual_length);
      received_len += transfer->actual_length;
      fp_dbg ("%s: received_len %u, expect len %u", G_STRFUNC, received_len, expect_len);
    }

  if (expect_len == 0)
    {
      //tls header
      evt_hdr_t *evt = (evt_hdr_t *) transfer->buffer;
      guint32 img_len = GUINT32_FROM_BE (evt->length);

      self->fpc_tls_buff_clear ();
      self->fpc_tls_buff_put (transfer->buffer + sizeof (evt_hdr_t), transfer->actual_length - sizeof (evt_hdr_t));

      expect_len = img_len;
      received_len += transfer->actual_length;
    }

  if (received_len >= expect_len)
    {
      received_len = 0;
      expect_len = 0;
      self->fpc_enclave_process_data (self->dev_ctx->enclave);
      fpi_ssm_next_state (transfer->ssm);
    }
  else
    {
      ssm_state = fpi_ssm_get_cur_state (transfer->ssm);
      fpi_ssm_jump_to_state (transfer->ssm, ssm_state);
    }

  fp_dbg ("exit <-- %s", G_STRFUNC);
}

static void
sm_wait4dead_pixel (FpiSsm   *ssm,
                    FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_dbg ("enter --> %s", G_STRFUNC);
  transfer->ssm = ssm;

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           fpc_read_dead_pixels,
                           NULL);
  fp_dbg ("exit <-- %s", G_STRFUNC);
}

static void
sm_wait4img (FpiSsm   *ssm,
             FpDevice *dev,
             guint32  *seq1)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_dbg ("enter --> %s", G_STRFUNC);
  transfer->ssm = ssm;

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           fpc_ssm_img_read_cb,
                           seq1);
  fp_dbg ("exit <-- %s", G_STRFUNC);
}

static gint32
fpc_save_template (FpPrint *print)
{
  gsize len;
  g_autofree char *base_path = NULL;
  g_autofree char *full_path = NULL;
  g_autoptr(GError) err = NULL;
  g_autofree char *buf = NULL;
  g_autofree char *dirpath = NULL;
  char finger_name[2] = {0};
  gint rst;

  g_assert(print);

  g_snprintf (finger_name, 2, "%x", fp_print_get_finger (print));
  base_path = g_build_filename ("/var/lib/fprint", fp_print_get_username (print), NULL);
  full_path  = g_build_filename (base_path,
                               fp_print_get_driver (print),
                               fp_print_get_device_id (print),
                               finger_name,
                               NULL);
  dirpath = g_path_get_dirname (full_path);
  rst = g_mkdir_with_parents (dirpath, 0700);
  if (rst < 0)
    {
      fp_err ("fpc_save_template : could not mkdir(\"%s\"): %s",
               dirpath, g_strerror (rst));
      return rst;
    }

  if (!fp_print_serialize (print, (guchar **) &buf, &len, &err))
    {
      fp_err ("fpc_save_template serialize err! %s", err->message);
      return -1;
    }

  //g_file_set_contents (path, buf, len, &err);
  g_file_set_contents (full_path, buf, len, &err);
  if (err)
    {
      fp_err ("fpc_save_template : could not save '%s': %s",
               full_path, err->message);

      return err->code;
    }

  fp_dbg ("fpc_save_template (): save to %s OK", full_path);

  return 0;
}

static int32_t
fpc_store_template_db (FpDevice *device, fpc_tee_bio_t * bio, FpPrint *print, guint32 update)
{
  GVariant *fpi_data = NULL;
  GVariant *uid = NULL;
  GVariant *blob_v = NULL;
  g_autofree gchar *user_id = NULL;
  gssize user_id_len;
  fpc_tee_t * tee = &bio->tee;
  int32_t result = 0;
  size_t blob_size = 0;
  g_autofree guint8 *blob = NULL;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  g_assert (print);
  g_assert (self);

  result = self->fpc_tee_get_db_blob_size (tee, &blob_size);
  if (result < 0)
    return result;
  else if (blob_size == 0)
    return -1;

  // If open fails ensure that we always close. REE/TEE could get out of sync
  result = self->fpc_tee_db_open (tee, FPC_TA_BIO_DB_RDONLY, blob_size);
  if (result < 0)
    {
      fp_err ("%s - transfer_open failed with %d\n", G_STRFUNC, result);
      return result;
    }

  blob = g_malloc0 (blob_size);
  if (!blob)
    {
      result = -1;
      self->fpc_tee_db_close (tee);
      return result;
    }
  memset (blob, 0, blob_size);

  // Transfer encrypted content from TA (chunk if necessary)
  result = self->fpc_tee_send_db_read_commands (tee, blob, blob_size);
  if (result < 0)
    {
      self->fpc_tee_db_close (tee);
      return result;
    }

  fp_dbg ("%s: blob_size %lu", G_STRFUNC, blob_size);

  user_id = fpi_print_generate_user_id (print);

  user_id_len = strlen (user_id);
  user_id_len = MIN (SECURITY_MAX_SID_SIZE, user_id_len);

  uid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                   user_id,
                                   user_id_len,
                                   1);

  blob_v = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                      blob,
                                      blob_size,
                                      1);

  fpi_data = g_variant_new ("(@ay@ay)",
                            blob_v,
                            uid);

  if (!update)
    fpi_print_set_type (print, FPI_PRINT_RAW);

  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", fpi_data, NULL);
  g_object_set (print, "description", user_id, NULL);

  fp_dbg ("user_id: %s", user_id);

  self->fpc_tee_db_close (tee);

  return result;
}

static void
fpc_enroll_suspend_resume_cb (FpiUsbTransfer *transfer,
                              FpDevice       *device,
                              gpointer        user_data,
                              GError         *error)
{
  int ssm_state = fpi_ssm_get_cur_state (transfer->ssm);

  fp_dbg ("%s current ssm state: %d", G_STRFUNC, ssm_state);

  if (ssm_state == FP_ENROLL_SUSPENDED)
    {
      if (error)
        fpi_ssm_mark_failed (transfer->ssm, error);

      fpi_device_suspend_complete (device, error);
      /* The resume handler continues to the next state! */
    }
  else if (ssm_state == FP_ENROLL_RESUME)
    {
      if (error)
        fpi_ssm_mark_failed (transfer->ssm, error);
      else
        fpi_ssm_jump_to_state (transfer->ssm, FP_ENROLL_CAPTURE);

      fpi_device_resume_complete (device, error);
    }

  return;
}

static void
fpc_enroll_sm_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  gint32 result = 0;
  FpiUsbTransfer *transfer = NULL;
  guint32 capture_id = FPC_CAPTUREID_RESERVED;
  guint32 g_seq1 = 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FP_ENROLL_BEGIN:
      {
        self->enroll_count = 0;
        result = self->fpc_tee_load_empty_db (self->dev_ctx->bio);
        if (result)
          {
            fp_err ("%s, fpc_tee_load_empty_db failed %d", G_STRFUNC, result);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
            break;
          }

        result = self->fpc_tee_begin_enroll (self->dev_ctx->bio);
        if (result)
          {
            fp_err ("%s, begin enroll failed %d", G_STRFUNC, result);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
            break;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case FP_ENROLL_CAPTURE:
      {
        self->fpc_tls_buff_clear ();
        fpc_write_ctrl (ssm, device, 0x02, 0x01, (guint8 *) &capture_id, sizeof (guint32), fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FP_ENROLL_WAIT4FINGERDOWN:
      {
        fp_dbg ("FP_VERIFY_WAIT4FINGERDOWN!");
        sm_wait4finger (ssm, device, fpc_enroll_wait4finger_cb);
      }
      break;

    case FP_ENROLL_GET_IMG:
      {
        fpc_write_ctrl (ssm, device, FPC_CMD_GET_IMG, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FP_ENROLL_WAIT4IMG_SEQ1:
    case FP_ENROLL_WAIT4IMG_SEQ2:
    case FP_ENROLL_WAIT4IMG_SEQ3:
    case FP_ENROLL_WAIT4IMG_SEQ4:
    case FP_ENROLL_WAIT4IMG_SEQ5:
    case FP_ENROLL_WAIT4IMG_SEQ6:
    case FP_ENROLL_WAIT4IMG_SEQ7:
    case FP_ENROLL_WAIT4IMG_SEQ8:
    case FP_ENROLL_WAIT4IMG_SEQ9:
    case FP_ENROLL_WAIT4IMG_SEQ10:
    case FP_ENROLL_WAIT4IMG_SEQ11:
      {
        g_seq1 = FP_ENROLL_WAIT4IMG_SEQ1;

        sm_wait4img (ssm, device, &g_seq1);
      }
      break;

    case FP_ENROLL_SEND_DEAD_PIXEL:
      {
        fpc_write_ctrl (ssm, device, 0x0A, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FP_ENROLL_READ_DEAD_PIXEL:
      {
        sm_wait4dead_pixel (ssm, device);
      }
      break;

    case FP_ENROLL_BINDID:
      {
        FpPrint *print = NULL;
        fpi_device_get_enroll_data (device, &print);
        result = fpc_store_template_db (device, self->dev_ctx->bio, print, 0);
        if (result)
          {
            fp_err ("%s, result %d", G_STRFUNC, result);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
            return;
          }

        fpc_write_ctrl (ssm, device, 0x13, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;
    case FP_ENROLL_END:
      {
        fpi_ssm_mark_completed (self->enroll_ssm);
      }
      break;

    case FP_ENROLL_SUSPENDED:
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC_CMD_INDICATE_S_STATE,
                                     FPC_HOST_MS_SX,
                                     0,
                                     0);

      fpi_usb_transfer_submit (transfer, CTRL_TIMEOUT, NULL,
                               fpc_enroll_suspend_resume_cb, NULL);
      break;

    case FP_ENROLL_RESUME:
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC_CMD_INDICATE_S_STATE,
                                     FPC_HOST_MS_S0,
                                     0,
                                     0);

      fpi_usb_transfer_submit (transfer, CTRL_TIMEOUT, NULL,
                               fpc_enroll_suspend_resume_cb, NULL);
      fpi_ssm_jump_to_state (ssm, FP_ENROLL_CAPTURE);

      break;

    case FP_ENROLL_DISCARD:
      {
        fpc_write_ctrl (ssm, device, 0x13, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;
    }
}

static void
fpc_enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);
  FpPrint *print = NULL;

  fp_info ("Enrollment complete!");

  self->enroll_ssm = NULL;

  if (fpi_ssm_get_error (ssm))
    error = fpi_ssm_dup_error (ssm);

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

/******************************************************************************
 *
 *  fpc_verify_xxx function
 *
 *****************************************************************************/

static int32_t
fpc_identify (FpDevice *device, guint32 *update)
{
  gint32 result = 0;
  guint32 ids[FPC_CONFIG_MAX_NR_TEMPLATES];
  guint32 size = FPC_CONFIG_MAX_NR_TEMPLATES;
  guint32 id = 0;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  memset (ids, 0, sizeof (ids));
  result = self->fpc_tee_get_finger_ids (self->dev_ctx->bio, &size, ids);
  if (size == 0)
    {
      fp_err ("no template to identify");
      return -1;
    }

  for (int i = 0; i < size; i++)
    fp_info ("ids[%d] = %u", i, ids[i]);

  result = self->fpc_tee_identify (self->dev_ctx->bio, &id);
  if (result)
    {
      fp_err ("%s, fpc_tee_identify failed %d", G_STRFUNC, result);
      return -2;
    }

  result = self->fpc_tee_update_template (self->dev_ctx->bio, update);
  if (result)
    fp_err ("%s, fpc_tee_update_template failed %d", G_STRFUNC, result);

  fp_dbg ("identify id = %u, update = %d", id, *update);

  return id != 0;
}

static void
fpc_report_result (FpDevice *device, FpPrint *print, gboolean is_match)
{
  if (is_match)
    {
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (device, FPI_MATCH_SUCCESS, NULL, NULL);
      else
        fpi_device_identify_report (device, print, NULL, NULL);

      return;
    }

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
  else
    fpi_device_identify_report (device, NULL, NULL, NULL);

  return;
}

static gint32
fpcmoh_match_report (FpDevice *device, fpc_tee_bio_t * bio)
{
  FpPrint *print = NULL;
  fpc_tee_t * tee = &bio->tee;
  gint32 result = 0;
  gint cnt = 0;
  const guint8 *user_id = NULL;
  const guint8 *blob = NULL;
  gsize user_id_len = 0;
  gsize blob_size = 0;

  g_autoptr(GPtrArray) templates = NULL;
  g_autoptr(GVariant) fpi_data = NULL;
  gboolean is_match = FALSE;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  guint32 update = 0;

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
    {
      templates = g_ptr_array_sized_new (1);
      fpi_device_get_verify_data (device, &print);
      g_ptr_array_add (templates, print);
    }
  else
    {
      fpi_device_get_identify_data (device, &templates);
      g_ptr_array_ref (templates);
    }

  if (NULL == templates)
    {
      fp_err ("%s: templates  NULL", G_STRFUNC);
      return -1;
    }

  fp_info ("%s: templates->len = %d", G_STRFUNC, templates->len);

  for (cnt = 0; cnt < templates->len; cnt++)
    {
      result = self->fpc_tee_load_empty_db (self->dev_ctx->bio);
      if (result)
        {
          fp_err ("%s, fpc_tee_load_empty_db failed %d", G_STRFUNC, result);
          return result;
        }

      print = g_ptr_array_index (templates, cnt);
      g_object_get (print, "fpi-data", &fpi_data, NULL);
      fp_dbg ("%s: fpi-data %p", G_STRFUNC, fpi_data);

      parse_print_data (fpi_data, &blob,  &blob_size, &user_id, &user_id_len);
      fp_dbg ("%s: user id: %s", G_STRFUNC, user_id);
      if (blob_size > 0)
        {
          result = self->fpc_tee_db_open (tee, FPC_TA_BIO_DB_WRONLY, blob_size);
          if (result < 0)
            {
              fp_err ("Failed to open transfer in write mode with %zu bytes of payload", blob_size);
              self->fpc_tee_db_close (tee);
              return result;
            }
        }
      else
        {
          fp_err ("%s: blob size 0", G_STRFUNC);
          result = -1;
          return result;
        }

      result = self->fpc_tee_send_db_write_commands (tee, blob, blob_size);
      if (result < 0)
        {
          self->fpc_tee_db_close (tee);
          return result;
        }
      self->fpc_tee_db_close (tee);

      if (fpc_identify (device, &update) > 0)
        {
          is_match = TRUE;
          break;
        }
    }

  if (is_match && update)
    {
      result = fpc_store_template_db (device, self->dev_ctx->bio, print, update);
      if (result)
        fp_err ("%s: fpc_store_template_db %d fail", G_STRFUNC, result);
      else
        result = fpc_save_template (print);
    }

  fpc_report_result (device, print, is_match);

  return result;
}

static void
fpc_verify_suspend_resume_cb (FpiUsbTransfer *transfer,
                              FpDevice       *device,
                              gpointer        user_data,
                              GError         *error)
{
  int ssm_state = fpi_ssm_get_cur_state (transfer->ssm);

  fp_dbg ("%s current ssm state: %d", G_STRFUNC, ssm_state);

  if (ssm_state == FP_VERIFY_SUSPENDED)
    {
      if (error)
        fpi_ssm_mark_failed (transfer->ssm, error);

      fpi_device_suspend_complete (device, error);
    }
  else if (ssm_state == FP_VERIFY_RESUME)
    {
      if (error)
        fpi_ssm_mark_failed (transfer->ssm, error);
      else
        fpi_ssm_jump_to_state (transfer->ssm, FP_VERIFY_CAPTURE);

      fpi_device_resume_complete (device, error);
    }

  return;
}

static void
fpc_verify_sm_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  FpiUsbTransfer *transfer = NULL;
  guint32 g_seq1 = 0;
  gint32 result = 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FP_VERIFY_CAPTURE:
      {
        guint32 capture_id = FPC_CAPTUREID_RESERVED;
        fpc_write_ctrl (ssm, device, 0x02, 0x01, (guint8 *) &capture_id, sizeof (guint32), fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FP_VERIFY_WAIT4FINGERDOWN:
      {
        fp_dbg ("FP_VERIFY_WAIT4FINGERDOWN!");
        sm_wait4finger (ssm, device, fpc_verify_wait4finger_cb);
      }
      break;

    case FP_VERIFY_GET_IMG:
      {
        fpc_write_ctrl (ssm, device, FPC_CMD_GET_IMG, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FP_VERIFY_WAIT4IMG_SEQ1:
    case FP_VERIFY_WAIT4IMG_SEQ2:
    case FP_VERIFY_WAIT4IMG_SEQ3:
    case FP_VERIFY_WAIT4IMG_SEQ4:
    case FP_VERIFY_WAIT4IMG_SEQ5:
    case FP_VERIFY_WAIT4IMG_SEQ6:
    case FP_VERIFY_WAIT4IMG_SEQ7:
    case FP_VERIFY_WAIT4IMG_SEQ8:
    case FP_VERIFY_WAIT4IMG_SEQ9:
    case FP_VERIFY_WAIT4IMG_SEQ10:
    case FP_VERIFY_WAIT4IMG_SEQ11:
      {
        g_seq1 = FP_VERIFY_WAIT4IMG_SEQ1;
        sm_wait4img (ssm, device, &g_seq1);
      }
      break;

    case FP_VERIFY_IDENTIFY:
      {
        result = fpcmoh_match_report (device, self->dev_ctx->bio);
        if (result)
          {
            fp_err ("%s result : %d ", G_STRFUNC, result);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
            return;
          }

        fpi_ssm_mark_completed (self->identify_ssm);
      }
      break;

    case FP_VERIFY_SUSPENDED:
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC_CMD_INDICATE_S_STATE,
                                     FPC_HOST_MS_SX,
                                     0,
                                     0);

      fpi_usb_transfer_submit (transfer, CTRL_TIMEOUT, NULL,
                               fpc_verify_suspend_resume_cb, NULL);
      break;

    case FP_VERIFY_RESUME:
      fp_dbg ("%s Notify Dev to resume", G_STRFUNC);
      transfer = fpi_usb_transfer_new (device);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_control (transfer,
                                     G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                     G_USB_DEVICE_RECIPIENT_DEVICE,
                                     FPC_CMD_INDICATE_S_STATE,
                                     FPC_HOST_MS_S0,
                                     0,
                                     0);

      fpi_usb_transfer_submit (transfer, CTRL_TIMEOUT, NULL,
                               fpc_verify_suspend_resume_cb, NULL);

      break;

    case FP_VERIFY_CANCEL:
      {
        fpc_write_ctrl (ssm, device, 0x03, 0x01, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;
    }
}

static void
fpc_verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_info ("Verify_identify complete!");

  if (fpi_ssm_get_error (ssm))
    error = fpi_ssm_dup_error (ssm);

  if (error && error->domain == FP_DEVICE_RETRY)
    {
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, g_steal_pointer (&error));
      else
        fpi_device_identify_report (dev, NULL, NULL, g_steal_pointer (&error));
    }

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);

  else
    fpi_device_identify_complete (dev, error);

  self->identify_ssm = NULL;
}

static int32_t
fpc_connect_tls (FpDevice *device, PDEVICE_CONTEXT pDevCtx)
{
  int32_t ret;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  g_assert (self);

  ret = self->fpc_tls_buff_init ();
  if (ret)
    {
      fp_err ("%s: fpc_tls_buff_init fail ret %d!", G_STRFUNC, ret);
      return -2;
    }

  ret = self->fpc_tls_write_buff_init ();
  if (ret)
    {
      fp_err ("%s: fpc_tls_write_buff_init fail ret %d!", G_STRFUNC, ret);
      self->fpc_tls_buff_release ();
      return -4;
    }

  ret = self->fpc_enclave_handle_tls_connection (pDevCtx->enclave, pDevCtx->tls_data, pDevCtx->tls_data_len);
  if (ret)
    {
      fp_err ("%s: fpc_enclave_handle_tls_connection, failded ret: %d", G_STRFUNC, ret);
      return ret;
    }

  return 0;
}

static int32_t
fpc_tls_ctx_init (FpDevice *device, PDEVICE_CONTEXT context)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  fp_dbg ("enter %s", G_STRFUNC);
  g_assert (self);
  context->enclave = self->fpc_create_enclave ();
  self->fpc_start_enclave (context->enclave);
  fp_dbg ("%s exit <--", G_STRFUNC);

  return 0;
}

static void
fpc_read_0b_cb (FpiUsbTransfer *transfer, FpDevice *device,
                gpointer user_data, GError *error)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  fp_dbg ("enter %s", G_STRFUNC);
  if (error)
    {
      fp_err ("%s error: %s ", G_STRFUNC, error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  g_assert (self->dev_ctx->tls_data);
  memcpy (self->dev_ctx->tls_data, transfer->buffer, 121);
  fpi_ssm_next_state (transfer->ssm);
}

static void
fpc_read_0b (FpiSsm *ssm, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 0x0b,
                                 0,
                                 0x00,
                                 121);
  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer,
                           CTRL_TIMEOUT,
                           NULL,
                           fpc_read_0b_cb,
                           NULL);
}


static int
fpc_init_evt_handler (FpDevice *device, uint8_t *data, uint32_t len)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  evt_hdr_t *evt = (evt_hdr_t *) data;

  if (len < sizeof (evt_initiated_t))
    {
      fp_err ("%s: len %u  struct len %lu err!", G_STRFUNC, len, sizeof (evt_initiated_t));
      return -1;
    }

  evt->cmdid = GUINT32_FROM_BE (evt->cmdid);

  if (0x02 != evt->cmdid)
    {
      fp_err ("%s: cmd id err (%u)", G_STRFUNC, evt->cmdid);
      return -1;
    }

  evt_initiated_t *ini = (evt_initiated_t *) data;

  PDEVICE_CONTEXT pDevCtx = self->dev_ctx;

  pDevCtx->img_w = GUINT16_FROM_BE (ini->img_w);
  pDevCtx->img_h = GUINT16_FROM_BE (ini->img_h);

  uint16_t hwid = GUINT16_FROM_BE (ini->hw_id);

  if (hwid)
    {
      if (pDevCtx->initialized == FALSE)
        {
          int32_t status = self->fpc_enclave_init (pDevCtx->enclave, hwid);
          if (status == 0)
            pDevCtx->initialized = TRUE;
          else
            fp_err ("%s: fpc_enclave_init failed with %d (hwid=%d)", G_STRFUNC, status, hwid);
        }
    }

  fp_dbg ("%s: hwid(%#04x), img_w %u, img_h %u", G_STRFUNC, hwid, pDevCtx->img_w, pDevCtx->img_h);
  fp_dbg ("%s: version: %s", G_STRFUNC, ini->fw_version);

  return 0;
}

static int
fpc_hello_evt_handler (FpDevice *device, uint8_t *data, uint32_t len)
{
  static gint32 received_len = 0;
  static gint32 expect_len = 0;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  g_assert(self);

  if (len < sizeof (evt_hdr_t))
    {
      fp_err ("%s: len %u struct len %lu err!", G_STRFUNC, len, sizeof (evt_hdr_t));
      return -1;
    }

  if (expect_len > received_len)
    {
      received_len += len;
      fp_dbg ("%s: tls data recevied len %u, expect len %u", G_STRFUNC, len, received_len);
      self->fpc_tls_buff_put (data, len);
    }

  if (expect_len == 0)
    {
      evt_hdr_t *evt = (evt_hdr_t *) data;

      evt->cmdid = GUINT32_FROM_BE (evt->cmdid);

      if (0x05 != evt->cmdid)
        {
          fp_dbg ("%s: cmd id error %u", G_STRFUNC, evt->cmdid);
          return -1;
        }

      expect_len = GUINT32_FROM_BE (evt->length);

      received_len += len;

      fp_dbg ("%s: evt 0x05 expect len %u (actual len %u) !", G_STRFUNC, expect_len, len);
      self->fpc_tls_buff_put (data + sizeof (evt_hdr_t), len - sizeof (evt_hdr_t));
    }

  if (expect_len > received_len)
    {
      return 1;
    }
  else
    {
      received_len = 0;
      expect_len = 0;
    }

  return 0;
}

static void
fpi_ssm_hello_receive_cb (FpiUsbTransfer *transfer, FpDevice *device,
                          gpointer unused_data, GError *error)
{
  g_return_if_fail (transfer->ssm);
  g_return_if_fail (transfer->buffer);

  fp_dbg ("%s: enter", G_STRFUNC);

  int ssm_state = fpi_ssm_get_cur_state (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, ssm_state);
      return;
    }

  int ret = fpc_hello_evt_handler (device, transfer->buffer, transfer->actual_length);

  if (ret == 1)
    {
      fpi_ssm_jump_to_state (transfer->ssm, ssm_state);
      return;
    }
  else if (ret == -1)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      //return after failed to avoid core dump
      return;
    }

  fpi_ssm_next_state (transfer->ssm);

  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
sm_wait4tls_data (FpiSsm *ssm, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_dbg ("enter %s", G_STRFUNC);

  transfer->ssm = ssm;

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           fpi_ssm_hello_receive_cb,
                           NULL);

  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_cmd_init_cb (FpiUsbTransfer *transfer, FpDevice *device,
                 gpointer unused_data, GError *error)
{
  g_return_if_fail (transfer->ssm);
  int ssm_state = 0;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  ssm_state = fpi_ssm_get_cur_state (transfer->ssm);

  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, ssm_state);
      return;
    }

  int ret = fpc_init_evt_handler (device, transfer->buffer, transfer->actual_length);

  if (ret)
    fpi_ssm_mark_failed (transfer->ssm,
                         fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));

  fpi_ssm_next_state (transfer->ssm);
}

static void
sm_wait4init_result (FpiSsm *ssm, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  fp_dbg ("enter %s", G_STRFUNC);

  transfer->ssm = ssm;

  fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           fpc_cmd_init_cb,
                           NULL);

  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_init_sm_run_state (FpiSsm *ssm, FpDevice *device)
{
  int32_t status = 0;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    //send abort to avoid POA
    case FPC_INIT_CMD_ABORT:
      fpc_write_ctrl (ssm, device, 0x03, 0x00, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      break;

    case FPC_INIT_CMD_INIT:
      fpc_write_ctrl (ssm, device, 0x01, 0x01, (uint8_t *) &(self->dev_ctx->yasc_session_id), sizeof (self->dev_ctx->yasc_session_id), fpi_ssm_usb_transfer_cb, NULL);
      break;

    case FPC_INIT_WAIT4INIT_RESULT:
      {
        sm_wait4init_result (ssm, device);
      }
      break;

    case FPC_INIT_WAKE_UP:
      fpc_write_ctrl (ssm, device, 0x08, FPC_HOST_MS_S0, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      break;

    case FPC_INIT_INIT:
      fpc_read_0b (ssm, device);
      break;

    case FPC_INIT_TLS_CONNECT:
      {
        status = fpc_connect_tls (device, self->dev_ctx);
        if (status)
          {
            fp_err ("%s result : %d ", G_STRFUNC, status);
            fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
            return;
          }

        fpi_ssm_next_state (ssm);
      }
      break;

    case FPC_INIT_TLS_HANDSHAKE_START:
      {
        fpc_write_ctrl (ssm, device, 0x05, 0x01, NULL, 0, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FPC_INIT_TLS_HANDSHAKE_WAIT4HELLO:
      {
        sm_wait4tls_data (ssm, device);
      }
      break;

    case FPC_INIT_TLS_HANDSHAKE_PROCESS:
      {
        status = self->fpc_enclave_tls_init_handshake (self->dev_ctx->enclave);
        fp_dbg ("%s: fpc_enclave_tls_init_handshake status %d", G_STRFUNC, status);

        if (FPC_TLS_HANDSHAKE_COMPLETE == self->fpc_enclave_get_tls_status (self->dev_ctx->enclave, &self->dev_ctx->tls_status))
          fpi_ssm_jump_to_state (ssm, FPC_INIT_TEE_INIT);
        else if (!self->fpc_tls_write_buff_is_empty ())
          fpi_ssm_next_state (ssm);
        else if (8 == self->dev_ctx->tls_status || 10 == self->dev_ctx->tls_status || 11 == self->dev_ctx->tls_status)
          fpi_ssm_jump_to_state (ssm, FPC_INIT_TLS_HANDSHAKE_WAIT4HELLO);
        else
          fpi_ssm_jump_to_state (ssm, FPC_INIT_TLS_HANDSHAKE_PROCESS);
      }
      break;

    case FPC_INIT_TLS_HANDSHAKE_WRITE:
      {
        size_t tls_hs_wr_len = 0;
        uint8_t hs_wr_buff[EP_IN_MAX_BUF_SIZE];
        uint32_t sent_len = 0;
        self->fpc_tls_write_buff_get ((uint8_t *) &tls_hs_wr_len, sizeof (size_t));
        g_assert (tls_hs_wr_len <= EP_IN_MAX_BUF_SIZE);
        sent_len = self->fpc_tls_write_buff_get (hs_wr_buff, tls_hs_wr_len);
        fp_dbg ("%s: tls_hs_wr_len %lu sent_len %u", G_STRFUNC, tls_hs_wr_len, sent_len);
        fpc_write_ctrl (ssm, device, 0x06, 0x01, hs_wr_buff, tls_hs_wr_len, fpi_ssm_usb_transfer_cb, NULL);
      }
      break;

    case FPC_INIT_TLS_HANDSHAKE_WROTEN:
      {
        fp_dbg ("%s: tls state %u", G_STRFUNC, self->dev_ctx->tls_status);
        if (!self->fpc_tls_write_buff_is_empty ())
          fpi_ssm_jump_to_state (ssm, FPC_INIT_TLS_HANDSHAKE_WRITE);
        else
          fpi_ssm_jump_to_state (ssm, FPC_INIT_TLS_HANDSHAKE_PROCESS);
      }
      break;

    case FPC_INIT_TEE_INIT:
      {
        self->dev_ctx->tee_handle = self->fpc_tee_init ();
        fp_dbg ("%s, fpc_tee_init hdl %p", G_STRFUNC, self->dev_ctx->tee_handle);
        if (!self->dev_ctx->tee_handle)
          {
            fp_err ("%s, fpc_tee_init failed", G_STRFUNC);
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          }
        self->dev_ctx->bio = self->fpc_tee_bio_init (self->dev_ctx->tee_handle);
        fp_dbg ("%s: bio %p, shb %p", G_STRFUNC, self->dev_ctx->bio, self->dev_ctx->bio->tee.shared_buffer);
        if (!self->dev_ctx->bio)
          {
            fp_err ("%s, fpc_tee_bio_init failed", G_STRFUNC);
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          }
        fpi_ssm_next_state (ssm);
      }
      break;
    }
}

static void
fpc_init_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (dev);

  if (fpi_ssm_get_error (ssm))
    error = fpi_ssm_dup_error (ssm);

  fpi_device_open_complete (dev, error);
  self->task_ssm = NULL;
  self->enroll_ssm = NULL;
  self->identify_ssm = NULL;
}

/******************************************************************************
 *
 *  Interface Function
 *
 *****************************************************************************/
static void
fpc_dev_probe (FpDevice *device)
{
  GUsbDevice *usb_dev;
  GError *error = NULL;
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  g_autofree gchar *product = NULL;
  gint productid = 0;

  fp_dbg ("%s enter --> ", G_STRFUNC);

  /* Claim usb interface */
  usb_dev = fpi_device_get_usb_device (device);
  if (!g_usb_device_open (usb_dev, &error))
    {
      fp_dbg ("%s g_usb_device_open failed %s", G_STRFUNC, error->message);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_reset (usb_dev, &error))
    {
      fp_dbg ("%s g_usb_device_reset failed %s", G_STRFUNC, error->message);

      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      fp_dbg ("%s g_usb_device_claim_interface failed %s", G_STRFUNC, error->message);

      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  product = g_usb_device_get_string_descriptor (usb_dev,
                                                g_usb_device_get_product_index (usb_dev),
                                                &error);
  if (product)
    fp_dbg ("Device name: %s", product);
  if (error)
    {
      fp_dbg ("%s g_usb_device_get_string_descriptor failed %s", G_STRFUNC, error->message);
      g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (device)),
                                      0, 0, NULL);
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  productid = g_usb_device_get_pid (usb_dev);
  // Default enroll scheme
  self->max_immobile_stage = 0;
  switch (productid)
    {
    case 0x9800:
      self->max_enroll_stage = MAX_ENROLL_SAMPLES;
      break;

    default:
      fp_warn ("Device %x is not supported", productid);
      self->max_enroll_stage = MAX_ENROLL_SAMPLES;
      break;
    }

  fpi_device_set_nr_enroll_stages (device, self->max_enroll_stage);
  g_usb_device_close (usb_dev, NULL);
  fpi_device_probe_complete (device, NULL, product, error);

  return;
}

static int32_t
fpc_tls_init (FpDevice *device, PDEVICE_CONTEXT device_context)
{
  int32_t result = 0;

  fp_dbg ("Enter %s, %d", G_STRFUNC, __LINE__);

  //the key buffer is 1000 bytes. We will receive 121 bytes encrypted key
  device_context->tls_data_len = 1000;
  device_context->tls_data = g_malloc (device_context->tls_data_len);
  if (!device_context->tls_data)
    {
      fp_err ("%s: tls_data g_malloc failed", G_STRFUNC);
      return result;
    }

  fp_dbg ("Exit %s, %d", G_STRFUNC, __LINE__);
  return result;
}

static void
fpc_dev_init (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  void    *handle;
  handle = dlopen("libfpcbep.so", RTLD_LAZY);
  if (!handle)
  {
    fp_err("%s\n", dlerror());
    fpi_device_open_complete (device,
                              fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
    return;
  }

  self->fpc_create_enclave = (fpc_create_enclave_t *) dlsym (handle, "fpc_create_enclave");
  g_assert (self->fpc_create_enclave);
  self->fpc_start_enclave = (fpc_start_enclave_t *) dlsym (handle, "fpc_start_enclave");
  g_assert (self->fpc_start_enclave);
  self->fpc_destroy_enclave = (fpc_destroy_enclave_t *) dlsym (handle, "fpc_destroy_enclave");
  g_assert (self->fpc_destroy_enclave);
  self->fpc_enclave_init = (fpc_enclave_init_t *) dlsym (handle, "fpc_enclave_init");
  g_assert (self->fpc_enclave_init);
  self->fpc_enclave_handle_tls_connection = (fpc_enclave_handle_tls_connection_t *) dlsym (handle, "fpc_enclave_handle_tls_connection");
  g_assert (self->fpc_enclave_handle_tls_connection);
  self->fpc_enclave_tls_init_handshake = (fpc_enclave_tls_init_handshake_t *) dlsym (handle, "fpc_enclave_tls_init_handshake");
  g_assert (self->fpc_enclave_tls_init_handshake);
  self->fpc_enclave_get_tls_status = (fpc_enclave_get_tls_status_t *) dlsym (handle, "fpc_enclave_get_tls_status");
  g_assert (self->fpc_enclave_get_tls_status);
  self->fpc_enclave_process_data = (fpc_enclave_process_data_t *) dlsym (handle, "fpc_enclave_process_data");
  g_assert (self->fpc_enclave_process_data);
  self->fpc_tee_bio_init = (fpc_tee_bio_init_t *) dlsym (handle, "fpc_tee_bio_init");
  g_assert (self->fpc_tee_bio_init);
  self->fpc_tee_begin_enroll = (fpc_tee_begin_enroll_t *) dlsym (handle, "fpc_tee_begin_enroll");
  g_assert (self->fpc_tee_begin_enroll);
  self->fpc_tee_enroll = (fpc_tee_enroll_t *) dlsym (handle, "fpc_tee_enroll");
  g_assert (self->fpc_tee_enroll);
  self->fpc_tee_end_enroll = (fpc_tee_end_enroll_t *) dlsym (handle, "fpc_tee_end_enroll");
  g_assert (self->fpc_tee_end_enroll);
  self->fpc_tee_identify = (fpc_tee_identify_t *) dlsym (handle, "fpc_tee_identify");
  g_assert (self->fpc_tee_identify);
  self->fpc_tee_update_template = (fpc_tee_update_template_t *) dlsym (handle, "fpc_tee_update_template");
  g_assert (self->fpc_tee_update_template);
  self->fpc_tee_get_finger_ids = (fpc_tee_get_finger_ids_t *) dlsym (handle, "fpc_tee_get_finger_ids");
  g_assert (self->fpc_tee_get_finger_ids);
  self->fpc_tee_load_empty_db = (fpc_tee_load_empty_db_t *) dlsym (handle, "fpc_tee_load_empty_db");
  g_assert (self->fpc_tee_load_empty_db);
  self->fpc_tee_get_db_blob_size = (fpc_tee_get_db_blob_size_t *) dlsym (handle, "fpc_tee_get_db_blob_size");
  g_assert (self->fpc_tee_get_db_blob_size);
  self->fpc_tee_db_open = (fpc_tee_db_open_t *) dlsym (handle, "fpc_tee_db_open");
  g_assert (self->fpc_tee_db_open);
  self->fpc_tee_db_close = (fpc_tee_db_close_t *) dlsym (handle, "fpc_tee_db_close");
  g_assert (self->fpc_tee_db_close);
  self->fpc_tee_send_db_read_commands = (fpc_tee_send_db_read_commands_t *) dlsym (handle, "fpc_tee_send_db_read_commands");
  g_assert (self->fpc_tee_send_db_read_commands);
  self->fpc_tee_send_db_write_commands = (fpc_tee_send_db_write_commands_t *) dlsym (handle, "fpc_tee_send_db_write_commands");
  g_assert (self->fpc_tee_send_db_write_commands);
  self->fpc_tls_buff_init = (fpc_tls_buff_init_t *) dlsym (handle, "fpc_tls_buff_init");
  g_assert (self->fpc_tls_buff_init);
  self->fpc_tls_buff_release = (fpc_tls_buff_release_t *) dlsym (handle, "fpc_tls_buff_release");
  g_assert (self->fpc_tls_buff_release);
  self->fpc_tls_buff_clear = (fpc_tls_buff_clear_t *) dlsym (handle, "fpc_tls_buff_clear");
  g_assert (self->fpc_tls_buff_clear);
  self->fpc_tls_buff_put = (fpc_tls_buff_put_t *) dlsym (handle, "fpc_tls_buff_put");
  g_assert (self->fpc_tls_buff_put);
  self->fpc_tls_write_buff_init = (fpc_tls_write_buff_init_t *) dlsym (handle, "fpc_tls_write_buff_init");
  g_assert (self->fpc_tls_write_buff_init);
  self->fpc_tls_write_buff_release = (fpc_tls_write_buff_release_t *) dlsym (handle, "fpc_tls_write_buff_release");
  g_assert (self->fpc_tls_write_buff_release);
  self->fpc_tls_write_buff_is_empty = (fpc_tls_write_buff_is_empty_t *) dlsym (handle, "fpc_tls_write_buff_is_empty");
  g_assert (self->fpc_tls_write_buff_is_empty);
  self->fpc_tls_write_buff_get = (fpc_tls_write_buff_get_t *) dlsym (handle, "fpc_tls_write_buff_get");
  g_assert (self->fpc_tls_write_buff_get);
  self->fpc_secure_random = (fpc_secure_random_t *) dlsym (handle, "fpc_secure_random");
  g_assert (self->fpc_secure_random);
  self->fpc_tee_init = (fpc_tee_init_t *) dlsym (handle, "fpc_tee_init");
  g_assert (self->fpc_tee_init);

  fp_dbg ("%s enter --> handle %p", G_STRFUNC, handle);
  GError *error = NULL;
  int32_t result = 0;

  self->dev_ctx = (PDEVICE_CONTEXT) g_malloc (sizeof (DEVICE_CONTEXT));
  if (!self->dev_ctx)
    {
      fp_err ("pDevCtx g_malloc failed\n");
      return;
    }
  memset (self->dev_ctx, 0, sizeof (DEVICE_CONTEXT));

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    {
      fp_err ("%s: g_usb_device_reset err %s\n", G_STRFUNC, error->message);
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  /* Claim usb interface */
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    {
      fp_err ("%s: g_usb_device_claim_interface err %s\n", G_STRFUNC, error->message);
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  fpc_tls_ctx_init (device, self->dev_ctx);
  result = self->fpc_secure_random ((uint8_t *) &(self->dev_ctx->yasc_session_id),
                              sizeof (self->dev_ctx->yasc_session_id));
  if (result)
    {
      fp_err ("%s, failed to generate radom session id", G_STRFUNC);
      return;
    }

  fpc_tls_init (device, self->dev_ctx);
  self->interrupt_cancellable = g_cancellable_new ();
  self->task_ssm = fpi_ssm_new (device, fpc_init_sm_run_state,
                                FPC_INIT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, fpc_init_ssm_done);
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_dev_exit (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);


  fp_dbg ("%s enter -->", G_STRFUNC);

  self->fpc_tls_write_buff_release ();
  self->fpc_tls_buff_release ();
  g_clear_pointer (&self->dev_ctx->tls_data, g_free);

  self->fpc_destroy_enclave (self->dev_ctx->enclave);

  self->dev_ctx->initialized = FALSE;

  g_clear_object (&self->interrupt_cancellable);
  fpc_dev_release_interface (self, NULL);
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_dev_verify_identify (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  fp_dbg ("%s enter -->", G_STRFUNC);
  self->identify_ssm = fpi_ssm_new_full (device, fpc_verify_sm_run_state,
                                         FP_VERIFY_NUM_STATES,
                                         FP_VERIFY_CANCEL,
                                         "verify_identify");
  fpi_ssm_start (self->identify_ssm, fpc_verify_ssm_done);
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_dev_enroll (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  fp_dbg ("%s enter -->", G_STRFUNC);

  self->enroll_stage = 0;
  self->immobile_stage = 0;
  self->enroll_ssm = fpi_ssm_new_full (device, fpc_enroll_sm_run_state,
                                       FP_ENROLL_NUM_STATES,
                                       FP_ENROLL_DISCARD,
                                       "enroll");
  fpi_ssm_start (self->enroll_ssm, fpc_enroll_ssm_done);
}

static void
fpc_dev_suspend (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);

  fp_dbg ("%s: action %u", G_STRFUNC, action);

  if (action != FPI_DEVICE_ACTION_VERIFY && action != FPI_DEVICE_ACTION_IDENTIFY && action != FPI_DEVICE_ACTION_ENROLL)
    {
      fpi_device_suspend_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  g_assert ((self->enroll_ssm && FP_ENROLL_WAIT4FINGERDOWN == fpi_ssm_get_cur_state (self->enroll_ssm)) ||
            (self->identify_ssm && FP_VERIFY_WAIT4FINGERDOWN == fpi_ssm_get_cur_state (self->identify_ssm)));

  self->cmd_suspended = TRUE;
  fp_dbg ("%s suspend %u", G_STRFUNC, self->cmd_suspended);
  g_cancellable_cancel (self->interrupt_cancellable);
  g_set_object (&self->interrupt_cancellable, g_cancellable_new ());

  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_dev_resume (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);

  fp_dbg ("%s enter -->", G_STRFUNC);

  if (action != FPI_DEVICE_ACTION_VERIFY && action != FPI_DEVICE_ACTION_IDENTIFY && action != FPI_DEVICE_ACTION_ENROLL)
    {
      g_assert_not_reached ();
      fpi_device_resume_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }

  g_assert (self->cmd_suspended);
  g_assert ((self->enroll_ssm && FP_ENROLL_SUSPENDED == fpi_ssm_get_cur_state (self->enroll_ssm)) ||
            (self->identify_ssm && FP_VERIFY_SUSPENDED == fpi_ssm_get_cur_state (self->identify_ssm)));

  self->cmd_suspended = FALSE;

  if (self->enroll_ssm)
    fpi_ssm_jump_to_state (self->enroll_ssm, FP_ENROLL_RESUME);
  else if (self->identify_ssm)
    fpi_ssm_jump_to_state (self->identify_ssm, FP_VERIFY_RESUME);

  fpi_device_resume_complete (device, NULL);
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpc_dev_cancel (FpDevice *device)
{
  FpiDeviceFpcMoh *self = FPI_DEVICE_FPCMOH (device);

  fp_dbg ("%s enter -->", G_STRFUNC);
  g_cancellable_cancel (self->interrupt_cancellable);
  g_set_object (&self->interrupt_cancellable, g_cancellable_new ());
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpi_device_fpcmoh_init (FpiDeviceFpcMoh *self)
{
  fp_dbg ("%s enter -->", G_STRFUNC);
  G_DEBUG_HERE ();
  fp_dbg ("%s exit <--", G_STRFUNC);
}

static void
fpi_device_fpcmoh_class_init (FpiDeviceFpcMohClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id =               FP_COMPONENT;
  dev_class->full_name =        "FPC MOH Fingerprint Sensor";
  dev_class->type =             FP_DEVICE_TYPE_USB;
  dev_class->scan_type =        FP_SCAN_TYPE_PRESS;
  dev_class->id_table =         id_table;
  dev_class->nr_enroll_stages = MAX_ENROLL_SAMPLES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open   =           fpc_dev_init;
  dev_class->close  =           fpc_dev_exit;
  dev_class->probe  =           fpc_dev_probe;
  dev_class->enroll =           fpc_dev_enroll;
  dev_class->verify   =         fpc_dev_verify_identify;
  dev_class->identify =         fpc_dev_verify_identify;
  dev_class->suspend =          fpc_dev_suspend;
  dev_class->resume =           fpc_dev_resume;
  dev_class->cancel =           fpc_dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
