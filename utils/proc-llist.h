/*
* proc-llist.h
* Copyright (c) 2009, 2020, 2026 Red Hat Inc.
* All Rights Reserved.
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#ifndef PROC_HEADER
#define PROC_HEADER

#include "config.h"
#include <stdbool.h>
#include <sys/types.h>	/* Ensure types in _lnode are defined on all systems */
#include "gcc-attributes.h"


/* This is the node of the linked list. Any data elements that are per
 *  record goes here. */
typedef struct _lnode{
  pid_t ppid;           // parent process ID
  pid_t pid;            // process ID
  uid_t uid;            // user ID
  char *cmd;		// command run by user
  unsigned long inode;	// inode of socket
  char *capabilities;	// Text of partial capabilities
  bool bounds;		// Show the bounding set marker
  bool ambient;		// Show the ambient set marker
  struct _lnode* next;	// Next node pointer
} lnode;

typedef struct {
	lnode *head;
	lnode *tail;
} llist;

/* Append takes ownership of the node and its strings. */
void list_append(llist *l, lnode *node)
	__attr_access ((__read_write__, 1))
	__attr_access ((__read_write__, 2));
void list_clear(llist *l)
	__attr_access ((__read_write__, 1));

/* Find the first matching socket owner at or after the given node. */
const lnode *list_find_inode(const lnode *node, unsigned long inode)
	__attr_access ((__read_only__, 1))
	__attribute_pure__;

#endif
