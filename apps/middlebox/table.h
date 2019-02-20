/**
 * @file table.h
 * @author Hyunwoo Lee
 * @date 1 May 2018
 * @brief The definition of functions to manage table.
 */

#ifndef __TABLE_H__
#define __TABLE_H__

#define MAX_ENTRIES 1000
#define MAX_NAME_LENGTH 256

struct forward_table
{
  int num_of_entries;
  unsigned char *forward_names[MAX_ENTRIES];
  int name_lengths[MAX_ENTRIES];
  unsigned char *forward_ips[MAX_ENTRIES];
  int ip_lengths[MAX_ENTRIES];
  int forward_ports[MAX_ENTRIES];
} *table;

int init_forward_table(unsigned char *filename);
void free_forward_table(void);

int insert_entry(unsigned char *name, int nlen, unsigned char *ip, int ilen, int port);
int find_by_name(unsigned char *buf, int len);
unsigned char *get_name_by_index(int index);
int get_name_length(int index);
unsigned char *get_ip_by_index(int index);
int get_port_by_index(int index);

#endif /* __TABLE_H__ */
