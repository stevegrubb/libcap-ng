/*
* proc-llist.c - Minimal linked list library
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

#include "config.h"
#include <stdlib.h>
#include "proc-llist.h"

void list_append(llist *l, lnode *node)
{
	node->next = NULL;
	if (l->tail)
		l->tail->next = node;
	else
		l->head = node;
	l->tail = node;
}

void list_clear(llist *l)
{
	while (l->head) {
		lnode *node = l->head;

		l->head = node->next;
		free(node->cmd);
		free(node->capabilities);
		free(node);
	}
	l->tail = NULL;
}

const lnode *list_find_inode(const lnode *node, unsigned long inode)
{
	while (node && node->inode != inode)
		node = node->next;
	return node;
}
