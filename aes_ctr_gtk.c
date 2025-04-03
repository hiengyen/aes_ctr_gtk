#include "aes.h"
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  GtkWidget *key_size_combo;
  GtkWidget *key_entry;
  GtkWidget *input_entry;
  GtkWidget *file_chooser;
  GtkWidget *output_text;
} AppWidgets;

void on_encrypt_button_clicked(GtkButton *button, AppWidgets *widgets) {
  const char *key_str = gtk_entry_get_text(GTK_ENTRY(widgets->key_entry));
  const char *input_str = gtk_entry_get_text(GTK_ENTRY(widgets->input_entry));
  int key_size_idx =
      gtk_combo_box_get_active(GTK_COMBO_BOX(widgets->key_size_combo));
  enum keySize size = (key_size_idx == 0)   ? SIZE_16
                      : (key_size_idx == 1) ? SIZE_24
                                            : SIZE_32;
  int key_len = (size == SIZE_16) ? 32 : (size == SIZE_24) ? 48 : 64;

  unsigned char *key = (unsigned char *)malloc(size);
  unsigned char nonce[8], *input_data, *output_data;
  int len;
  char result[8192] = {0};
  TimingResult timing = {0};

  if (strlen(key_str) != key_len) {
    snprintf(result, sizeof(result), "Key must be %d HEX characters!", key_len);
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)), result,
        -1);
    free(key);
    return;
  }

  for (int i = 0; i < size; i++) {
    if (sscanf(key_str + 2 * i, "%2hhx", &key[i]) != 1) {
      gtk_text_buffer_set_text(
          gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
          "Invalid HEX key format!", -1);
      free(key);
      return;
    }
  }

  len = strlen(input_str);
  if (len < 15) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "Input must be at least 15 characters!", -1);
    free(key);
    return;
  }

  input_data = (unsigned char *)malloc(len);
  output_data = (unsigned char *)malloc(len);
  memcpy(input_data, input_str, len);

  if (generate_nonce(nonce, 8) != SUCCESS) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "Failed to generate nonce!", -1);
    free(input_data);
    free(output_data);
    free(key);
    return;
  }

  aes_ctr_crypt(input_data, output_data, len, key, nonce, size, &timing);
  write_file("encrypted.bin", nonce, output_data, len);

  snprintf(result, sizeof(result), "Plaintext (HEX): ");
  for (int i = 0; i < len; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%02x ",
             input_data[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nNonce (HEX): ");
  for (int i = 0; i < 8; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%02x ",
             nonce[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nCiphertext (HEX): ");
  for (int i = 0; i < len; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%02x ",
             output_data[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nEncryption Time: %.2f ms\nEncryption successful !Saved to "
           "encrypted.bin ",
           timing.encryption_time);
  gtk_text_buffer_set_text(
      gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)), result,
      -1);

  if (strlen(result) >= sizeof(result) - 1) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "Output too large to display!", -1);
  }

  free(input_data);
  free(output_data);
  free(key);
}

void on_decrypt_button_clicked(GtkButton *button, AppWidgets *widgets) {
  const char *key_str = gtk_entry_get_text(GTK_ENTRY(widgets->key_entry));
  const char *file_path =
      gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widgets->file_chooser));

  int key_size_idx =
      gtk_combo_box_get_active(GTK_COMBO_BOX(widgets->key_size_combo));
  enum keySize size = (key_size_idx == 0)   ? SIZE_16
                      : (key_size_idx == 1) ? SIZE_24
                                            : SIZE_32;
  int key_len = (size == SIZE_16) ? 32 : (size == SIZE_24) ? 48 : 64;
  unsigned char *key = (unsigned char *)malloc(size);
  unsigned char nonce[8], *input_data, *output_data;
  size_t len;
  char result[8192] = {0};
  TimingResult timing = {0};

  if (strlen(key_str) != key_len) {
    snprintf(result, sizeof(result), "Key must be %d HEX characters!", key_len);
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)), result,
        -1);
    free(key);
    return;
  }
  for (int i = 0; i < size; i++) {
    if (sscanf(key_str + 2 * i, "%2hhx", &key[i]) != 1) {
      gtk_text_buffer_set_text(
          gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
          "Invalid HEX key format!", -1);
      free(key);
      return;
    }
  }

  if (!file_path || read_file(file_path, &input_data, &len) != SUCCESS) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "Failed to read file!", -1);
    free(key);
    return;
  }
  if (len < 8) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "File too short, missing nonce or ciphertext!", -1);
    free(input_data);
    free(key);
    return;
  }

  memcpy(nonce, input_data, 8);
  int ciphertext_len = len - 8;
  unsigned char *ciphertext = input_data + 8;
  output_data = (unsigned char *)malloc(ciphertext_len);

  aes_ctr_crypt(ciphertext, output_data, ciphertext_len, key, nonce, size,
                &timing);
  write_decrypted_file("decrypted.txt", output_data, ciphertext_len);

  snprintf(result, sizeof(result), "Nonce (HEX): ");
  for (int i = 0; i < 8; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%02x ",
             nonce[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nCiphertext (HEX): ");
  for (int i = 0; i < ciphertext_len; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%02x ",
             ciphertext[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nDecrypted text: ");
  for (int i = 0; i < ciphertext_len; i++)
    snprintf(result + strlen(result), sizeof(result) - strlen(result), "%c",
             output_data[i]);
  snprintf(result + strlen(result), sizeof(result) - strlen(result),
           "\nDecryption Time: %.2f ms\nDecryption successful !Saved to "
           "decrypted.txt",
           timing.decryption_time);
  gtk_text_buffer_set_text(
      gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)), result,
      -1);

  if (strlen(result) >= sizeof(result) - 1) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)),
        "Output too large to display!", -1);
  }

  free(input_data);
  free(output_data);
  free(key);
}

int main(int argc, char *argv[]) {
  gtk_init(&argc, &argv);

  GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "AES with CTR Mode");
  gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
  gtk_container_add(GTK_CONTAINER(window), main_box);
  gtk_container_set_border_width(GTK_CONTAINER(main_box), 10);

  AppWidgets widgets;

  GtkWidget *input_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
  gtk_box_pack_start(GTK_BOX(main_box), input_box, FALSE, FALSE, 0);

  GtkWidget *key_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
  GtkWidget *key_label = gtk_label_new("Key (HEX):");
  gtk_box_pack_start(GTK_BOX(key_box), key_label, FALSE, FALSE, 0);
  widgets.key_entry = gtk_entry_new();
  gtk_entry_set_placeholder_text(GTK_ENTRY(widgets.key_entry),
                                 "e.g., 2b7e151628aed2a6abf7158809cf4f3c");
  gtk_box_pack_start(GTK_BOX(key_box), widgets.key_entry, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(input_box), key_box, FALSE, FALSE, 0);

  GtkWidget *key_size_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
  GtkWidget *key_size_label = gtk_label_new("Key Size:");
  gtk_box_pack_start(GTK_BOX(key_size_box), key_size_label, FALSE, FALSE, 0);
  widgets.key_size_combo = gtk_combo_box_text_new();
  gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(widgets.key_size_combo),
                                 "128-bit");
  gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(widgets.key_size_combo),
                                 "192-bit");
  gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(widgets.key_size_combo),
                                 "256-bit");
  gtk_combo_box_set_active(GTK_COMBO_BOX(widgets.key_size_combo),
                           0); // Default 128-bit
  gtk_box_pack_start(GTK_BOX(key_size_box), widgets.key_size_combo, TRUE, TRUE,
                     0);
  gtk_box_pack_start(GTK_BOX(input_box), key_size_box, FALSE, FALSE, 0);

  GtkWidget *input_data_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
  GtkWidget *input_label = gtk_label_new("Input (min 15 chars):");
  gtk_box_pack_start(GTK_BOX(input_data_box), input_label, FALSE, FALSE, 0);
  widgets.input_entry = gtk_entry_new();
  gtk_entry_set_placeholder_text(GTK_ENTRY(widgets.input_entry),
                                 "e.g., HelloWorld1234567");
  gtk_box_pack_start(GTK_BOX(input_data_box), widgets.input_entry, TRUE, TRUE,
                     0);
  gtk_box_pack_start(GTK_BOX(input_box), input_data_box, FALSE, FALSE, 0);

  GtkWidget *file_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
  GtkWidget *file_label = gtk_label_new("Ciphertext file:");
  gtk_box_pack_start(GTK_BOX(file_box), file_label, FALSE, FALSE, 0);
  widgets.file_chooser =
      gtk_file_chooser_button_new("Select file", GTK_FILE_CHOOSER_ACTION_OPEN);
  gtk_box_pack_start(GTK_BOX(file_box), widgets.file_chooser, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(input_box), file_box, FALSE, FALSE, 0);

  GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
  gtk_box_set_homogeneous(GTK_BOX(button_box), TRUE);
  gtk_box_pack_start(GTK_BOX(main_box), button_box, FALSE, FALSE, 0);

  GtkWidget *encrypt_button = gtk_button_new_with_label("Encrypt");
  gtk_box_pack_start(GTK_BOX(button_box), encrypt_button, TRUE, TRUE, 0);
  g_signal_connect(encrypt_button, "clicked",
                   G_CALLBACK(on_encrypt_button_clicked), &widgets);

  GtkWidget *decrypt_button = gtk_button_new_with_label("Decrypt");
  gtk_box_pack_start(GTK_BOX(button_box), decrypt_button, TRUE, TRUE, 0);
  g_signal_connect(decrypt_button, "clicked",
                   G_CALLBACK(on_decrypt_button_clicked), &widgets);

  GtkWidget *clear_button = gtk_button_new_with_label("Clear");
  gtk_box_pack_start(GTK_BOX(button_box), clear_button, TRUE, TRUE, 0);
  void on_clear_button_clicked(GtkButton * button, AppWidgets * widgets) {
    gtk_text_buffer_set_text(
        gtk_text_view_get_buffer(GTK_TEXT_VIEW(widgets->output_text)), "", -1);
  }
  g_signal_connect(clear_button, "clicked", G_CALLBACK(on_clear_button_clicked),
                   &widgets);

  widgets.output_text = gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(widgets.output_text), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(widgets.output_text),
                              GTK_WRAP_WORD_CHAR);
  GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_container_add(GTK_CONTAINER(scrolled_window), widgets.output_text);
  gtk_box_pack_start(GTK_BOX(main_box), scrolled_window, TRUE, TRUE, 0);

  gtk_widget_show_all(window);
  gtk_main();

  return 0;
}
