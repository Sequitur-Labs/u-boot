/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#ifndef _LIST_H
#define _LIST_H

#include <malloc.h>

#define MALLOC malloc
#define FREE free

typedef struct entry entry_t;

struct entry
{
	void* data;
	entry_t* next;
	entry_t* prev;
};


typedef struct list
{
	entry_t* head;
	entry_t* tail;
} list_t;


typedef int (*ITERFUNC)(entry_t* item,void* data);



list_t* newList( void );
void appendEntry(list_t* list,void* data);
void deleteEntry(list_t* list,entry_t* entry);
void freeList(list_t* list,ITERFUNC freefunc);
int iterateList(list_t* list,entry_t* start,ITERFUNC callback,void* data);
entry_t* searchList(list_t* list,entry_t* start,ITERFUNC compback,void* data);
int getListCount(list_t* list);


#endif
